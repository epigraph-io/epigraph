# Alt-Set Lifecycle Labels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add operational lifecycle to `alternative_of` members: three reserved labels (`alt-chosen`, `alt-rejected`, `alt-deferred`), optional `properties.alt_state_meta` metadata, a `alt_set_decisions` SQL view, and two new optional params on `suggest_alternative_sets`. File backlog items (B) and (C) with promotion triggers. Closes the v1 (A.1 + A.3) scope of `docs/superpowers/specs/2026-05-27-alt-set-lifecycle-design.md`.

**Architecture:** No new claim types, no new edge types. Labels are free-form `text[]` (EpiGraph has no allow-list today), so the three reserved labels need no code admission. The work is: one migration adding `alt_set_decisions` view (joins `alternative_set` view from PR #187 with `claims.labels` / `claims.properties`), two MCP tool params extending `scan_candidates` SQL in `crates/epigraph-mcp/src/tools/alternative_sets.rs`, integration tests, and two backlog claims via `mcp__epigraph__memorize`.

**Tech Stack:** Postgres (view), Rust, sqlx, `epigraph-api`, `epigraph-mcp`, MCP `memorize` for backlog filings.

---

## Setup

**Branch from `origin/main`** (PRs #185 and #187 are merged; migrations 041 and 042 are present):

```bash
cd /home/jeremy/epigraph
git fetch origin main
git checkout -b feat/alt-set-lifecycle origin/main
```

**Test database** per `CLAUDE.md`:

```bash
export DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test'
```

**Spec reference:** `docs/superpowers/specs/2026-05-27-alt-set-lifecycle-design.md`.

**Migration slot:** `043`. Confirm at start with `ls migrations/ | sort | tail -5` — should show `040_workflows_goal_embedding.sql`, `041_same_source_papers_function.sql`, `042_alternative_of_edge_type.sql`. If `043` is taken when you reach the implementation step, renumber to the next free slot per the existing `chore(db): renumber migration NN→MM` pattern (PRs #177, #178).

**Carry the spec into the branch:** the spec is on `spec/alt-set-lifecycle` (commits `a35b51e`, `45dc4b1`). Cherry-pick into this branch so the implementation PR includes the design doc:

```bash
git cherry-pick a35b51e 45dc4b1
```

---

### Task 1: `alt_set_decisions` view migration

**Files:**
- Create: `migrations/043_alt_set_decisions_view.sql`

- [ ] **Step 1: Write the migration**

```sql
-- 043_alt_set_decisions_view.sql
--
-- Operational lifecycle for alt-set members. Joins migration 042's
-- alternative_set view (transitive-closure equivalence classes) with
-- claims.labels and claims.properties to surface the current
-- decision state per member.
--
-- See docs/superpowers/specs/2026-05-27-alt-set-lifecycle-design.md.

CREATE OR REPLACE VIEW alt_set_decisions AS
SELECT
    a.claim_id,
    a.alt_members,
    CASE
        WHEN c.labels @> ARRAY['alt-chosen']   THEN 'chosen'
        WHEN c.labels @> ARRAY['alt-rejected'] THEN 'rejected'
        WHEN c.labels @> ARRAY['alt-deferred'] THEN 'deferred'
        ELSE 'active'
    END AS alt_state,
    c.properties -> 'alt_state_meta' AS alt_state_meta,
    c.pignistic_prob,
    c.belief,
    c.plausibility
FROM alternative_set a
JOIN claims c ON c.id = a.claim_id;

COMMENT ON VIEW alt_set_decisions IS
'Per-member lifecycle state for alt-set claims. alt_state is derived from the '
'first matching reserved label in priority order chosen > rejected > deferred > active. '
'alt_state_meta is the optional JSONB metadata bag (transitioned_at, transitioned_by, '
'rationale, score). pignistic_prob/belief/plausibility are included so operators can '
'rank candidates without a follow-up join.';
```

- [ ] **Step 2: Apply and confirm**

```bash
cd /home/jeremy/epigraph
PGPASSWORD=epigraph createdb -h localhost -U epigraph epigraph_db_lifecycle_smoke 2>&1
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_lifecycle_smoke' sqlx migrate run 2>&1 | tail -3
PGPASSWORD=epigraph psql -h localhost -U epigraph -d epigraph_db_lifecycle_smoke -c "\\d+ alt_set_decisions" | head -20
PGPASSWORD=epigraph dropdb -h localhost -U epigraph epigraph_db_lifecycle_smoke
```

Expected: view exists with columns `claim_id, alt_members, alt_state, alt_state_meta, pignistic_prob, belief, plausibility`.

- [ ] **Step 3: Commit**

```bash
git add migrations/043_alt_set_decisions_view.sql
git commit -m "feat(db): alt_set_decisions view (alt-set lifecycle labels)"
```

---

### Task 2: View integration test

**Files:**
- Create: `crates/epigraph-api/tests/alt_set_decisions_view_test.rs`

- [ ] **Step 1: Write the test**

```rust
//! Verifies alt_set_decisions correctly classifies alt-set members by
//! their lifecycle label and surfaces alt_state_meta.

mod common;

use sqlx::{PgPool, Row};

#[sqlx::test(migrations = "../../migrations")]
async fn alt_set_decisions_classifies_by_label(pool: PgPool) {
    // Three claims forming an alt-set: a1 alternative_of a2, a2 alternative_of a3
    // (transitive closure collapses {a1, a2, a3} into one equivalence class).
    let a1 = common::seed_claim(&pool, "alt member 1").await;
    let a2 = common::seed_claim(&pool, "alt member 2").await;
    let a3 = common::seed_claim(&pool, "alt member 3").await;
    common::insert_edge(&pool, a1, a2, "claim", "claim", "alternative_of").await;
    common::insert_edge(&pool, a2, a3, "claim", "claim", "alternative_of").await;

    // a1 = chosen, a2 = rejected, a3 = default active
    sqlx::query("UPDATE claims SET labels = ARRAY['alt-chosen'] WHERE id = $1")
        .bind(a1).execute(&pool).await.unwrap();
    sqlx::query("UPDATE claims SET labels = ARRAY['alt-rejected'] WHERE id = $1")
        .bind(a2).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE claims SET properties = jsonb_build_object('alt_state_meta', \
         jsonb_build_object('state', 'chosen', 'rationale', 'cheap', 'score', \
         jsonb_build_object('cost', 0.7, 'time', 0.5))) WHERE id = $1",
    ).bind(a1).execute(&pool).await.unwrap();

    let rows = sqlx::query(
        "SELECT claim_id, alt_state, alt_state_meta IS NOT NULL AS has_meta \
         FROM alt_set_decisions WHERE claim_id = ANY($1) ORDER BY alt_state",
    ).bind(&[a1, a2, a3][..]).fetch_all(&pool).await.unwrap();

    assert_eq!(rows.len(), 3, "expected 3 rows in the equivalence class");

    let states: Vec<(uuid::Uuid, String, bool)> = rows.iter().map(|r| (
        r.get::<uuid::Uuid, _>("claim_id"),
        r.get::<String, _>("alt_state"),
        r.get::<bool, _>("has_meta"),
    )).collect();

    let a1_row = states.iter().find(|(id, _, _)| *id == a1).expect("a1 row");
    let a2_row = states.iter().find(|(id, _, _)| *id == a2).expect("a2 row");
    let a3_row = states.iter().find(|(id, _, _)| *id == a3).expect("a3 row");

    assert_eq!(a1_row.1, "chosen");  assert!(a1_row.2,  "a1 has alt_state_meta");
    assert_eq!(a2_row.1, "rejected"); assert!(!a2_row.2, "a2 has no meta");
    assert_eq!(a3_row.1, "active");   assert!(!a3_row.2, "a3 default no meta");
}

#[sqlx::test(migrations = "../../migrations")]
async fn alt_set_decisions_priority_chosen_over_rejected(pool: PgPool) {
    // If a claim has BOTH alt-chosen AND alt-rejected (invariant violation —
    // shouldn't happen in practice), the view's CASE picks 'chosen'.
    let a = common::seed_claim(&pool, "double-labelled").await;
    let b = common::seed_claim(&pool, "other").await;
    common::insert_edge(&pool, a, b, "claim", "claim", "alternative_of").await;

    sqlx::query("UPDATE claims SET labels = ARRAY['alt-chosen', 'alt-rejected'] WHERE id = $1")
        .bind(a).execute(&pool).await.unwrap();

    let state: String = sqlx::query_scalar(
        "SELECT alt_state FROM alt_set_decisions WHERE claim_id = $1"
    ).bind(a).fetch_one(&pool).await.unwrap();
    assert_eq!(state, "chosen", "chosen priority over rejected");
}
```

If `crates/epigraph-api/tests/common/mod.rs` lacks `seed_claim` / `insert_edge`, port from existing patterns (e.g., `alternative_of_symmetric_dedup.rs` from PR #187 — already proven to work with `#[sqlx::test(migrations = "../../migrations")]`).

- [ ] **Step 2: Run the test**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test -p epigraph-api --test alt_set_decisions_view_test -- --nocapture
```

Expected: 2 passed.

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-api/tests/alt_set_decisions_view_test.rs
git commit -m "test(api): alt_set_decisions view classifies by label + priority"
```

---

### Task 3: Extend `SuggestAlternativeSetsParams` and `scan_candidates` SQL

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/alternative_sets.rs`

- [ ] **Step 1: Read the current shape**

```bash
cat /home/jeremy/epigraph/crates/epigraph-mcp/src/tools/alternative_sets.rs
```

Confirm the file contains `SuggestAlternativeSetsParams`, `SuggestedAlternativePair`, public `suggest_alternative_sets`, file-private `scan_candidates`.

- [ ] **Step 2: Extend the params struct**

In `crates/epigraph-mcp/src/tools/alternative_sets.rs`, add two fields to `SuggestAlternativeSetsParams`:

```rust
/// Drop candidate pairs whose members are already labelled alt-chosen or
/// alt-rejected (settled). Default true — settled pairs are not useful
/// suggestions. Set false to surface everything (pre-PR behavior).
#[serde(default = "default_exclude_settled")]
pub exclude_settled: bool,

/// Surface pairs where one member is alt-rejected and the rival has BetP
/// higher by at least `min_pair_strength`. Useful for reconsidering
/// previously-rejected pathways when a stronger alternative appears.
/// Default false — opt-in only.
#[serde(default)]
pub surface_reconsiderations: bool,
```

Add the default function alongside the existing `default_min_strength`:

```rust
fn default_exclude_settled() -> bool {
    true
}
```

- [ ] **Step 3: Extend the SQL in `scan_candidates`**

The existing query (per PR #187) finds pairs of supporters of a shared target connected by `contradicts` but not by `alternative_of`. Replace it with:

```rust
async fn scan_candidates(
    pool: &PgPool,
    target_filter: Option<Uuid>,
    min_strength: f64,
    exclude_settled: bool,
    surface_reconsiderations: bool,
) -> Result<Vec<SuggestedAlternativePair>, sqlx::Error> {
    let rows: Vec<(Uuid, Uuid, Uuid, f64, String)> = sqlx::query_as(
        r#"
        WITH base AS (
            SELECT
                LEAST(s1.source_id, s2.source_id)    AS claim_a,
                GREATEST(s1.source_id, s2.source_id) AS claim_b,
                s1.target_id                         AS target_claim,
                LEAST(
                    COALESCE(ca.pignistic_prob, 0.0),
                    COALESCE(cb.pignistic_prob, 0.0)
                ) AS score,
                COALESCE(ca.pignistic_prob, 0.0) AS bp_a,
                COALESCE(cb.pignistic_prob, 0.0) AS bp_b,
                COALESCE(ca.labels, ARRAY[]::text[]) AS labels_a,
                COALESCE(cb.labels, ARRAY[]::text[]) AS labels_b
            FROM edges s1
            JOIN edges s2
              ON s2.target_id = s1.target_id
             AND s2.relationship = 'supports'
             AND s2.source_id <> s1.source_id
            JOIN edges contr
              ON ((contr.source_id = s1.source_id AND contr.target_id = s2.source_id)
               OR (contr.source_id = s2.source_id AND contr.target_id = s1.source_id))
             AND contr.relationship = 'contradicts'
            JOIN claims ca ON ca.id = s1.source_id
            JOIN claims cb ON cb.id = s2.source_id
            LEFT JOIN edges existing
              ON existing.relationship = 'alternative_of'
             AND ((existing.source_id = s1.source_id AND existing.target_id = s2.source_id)
               OR (existing.source_id = s2.source_id AND existing.target_id = s1.source_id))
            WHERE s1.relationship = 'supports'
              AND s1.source_id < s2.source_id
              AND ($1::uuid IS NULL OR s1.target_id = $1)
              AND existing.id IS NULL
        )
        SELECT
            claim_a, claim_b, target_claim, score,
            CASE
                WHEN $4 AND ('alt-rejected' = ANY(labels_a) OR 'alt-rejected' = ANY(labels_b))
                  THEN format(
                      'reconsider: one supporter is alt-rejected; rivals'' BetPs are %s and %s',
                      bp_a::text, bp_b::text)
                ELSE format('contradicts edge between supporters of %s', target_claim::text)
            END AS reason
        FROM base
        WHERE
            -- Pure heuristic gate: at least one supporter has BetP >= threshold
            score >= $2
            -- Exclusion of settled pairs (chosen/rejected) when exclude_settled = true,
            -- unless surface_reconsiderations is on and exactly one member is alt-rejected
            -- with a sufficient BetP gap to its rival.
            AND (
                NOT $3                     -- if exclude_settled is false, accept everything past score
                OR (
                    NOT ('alt-chosen'   = ANY(labels_a) OR 'alt-chosen'   = ANY(labels_b))
                    AND (
                        NOT ('alt-rejected' = ANY(labels_a) OR 'alt-rejected' = ANY(labels_b))
                        OR (
                            $4  -- surface_reconsiderations
                            AND (
                                -- exactly-one rejected
                                ('alt-rejected' = ANY(labels_a)) <> ('alt-rejected' = ANY(labels_b))
                            )
                            AND abs(bp_a - bp_b) >= $2
                        )
                    )
                )
            )
        ORDER BY score DESC
        LIMIT 200
        "#,
    )
    .bind(target_filter)
    .bind(min_strength)
    .bind(exclude_settled)
    .bind(surface_reconsiderations)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(a, b, t, score, reason)| {
        SuggestedAlternativePair {
            claim_a: a,
            claim_b: b,
            target_claim: t,
            score,
            reason,
        }
    }).collect())
}
```

Note: the previous `scan_candidates` had four positional params (`target_filter`, `min_strength`); this version adds two (`exclude_settled`, `surface_reconsiderations`) and the body computes `reason` in SQL so it includes BetPs when reconsidering.

- [ ] **Step 4: Update the caller**

In the same file, update `suggest_alternative_sets` to thread the new params:

```rust
pub async fn suggest_alternative_sets(
    server: &EpiGraphMcpFull,
    params: SuggestAlternativeSetsParams,
) -> Result<CallToolResult, McpError> {
    let target_filter = match params.target_claim_id.as_deref() {
        Some(s) => Some(parse_uuid(s)?),
        None => None,
    };
    let min_strength = params.min_pair_strength.clamp(0.0, 1.0);

    let candidates = scan_candidates(
        &server.pool,
        target_filter,
        min_strength,
        params.exclude_settled,
        params.surface_reconsiderations,
    )
    .await
    .map_err(internal_error)?;

    success_json(&SuggestAlternativeSetsResponse { candidates })
}
```

- [ ] **Step 5: Build clean**

```bash
SQLX_OFFLINE=true cargo check -p epigraph-mcp
cargo fmt -- crates/epigraph-mcp/src/tools/alternative_sets.rs
cargo clippy -p epigraph-mcp --lib -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Do NOT commit yet — Task 4 commits jointly with this**

---

### Task 4: Tool integration tests for the two new params

**Files:**
- Modify: `crates/epigraph-mcp/tests/suggest_alternative_sets.rs` (existing file from PR #187)

- [ ] **Step 1: Read the existing test file**

```bash
cat /home/jeremy/epigraph/crates/epigraph-mcp/tests/suggest_alternative_sets.rs | head -80
```

Note the existing fixture pattern (direct call into `epigraph_mcp::tools::alternative_sets::suggest_alternative_sets`).

- [ ] **Step 2: Add four new tests**

Append the following test functions to the existing file. The existing tests should continue to use the new defaults (`exclude_settled=true`, `surface_reconsiderations=false`) — they may need explicit `exclude_settled: false` if their seeds include any labels; verify and add as needed.

```rust
#[sqlx::test(migrations = "../../migrations")]
async fn exclude_settled_default_drops_chosen_pair(pool: PgPool) {
    let server = common::build_test_server(pool.clone()).await;
    let t  = common::seed_claim(&pool, "Target").await;
    let a1 = common::seed_claim_with_truth(&pool, "A1", 0.7).await;
    let a2 = common::seed_claim_with_truth(&pool, "A2", 0.6).await;
    common::insert_edge(&pool, a1, t, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a2, t, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a1, a2, "claim", "claim", "contradicts").await;
    // Mark a1 as alt-chosen — should suppress this pair under default behavior
    sqlx::query("UPDATE claims SET labels = ARRAY['alt-chosen'] WHERE id = $1")
        .bind(a1).execute(&pool).await.unwrap();

    let resp = epigraph_mcp::tools::alternative_sets::suggest_alternative_sets(
        &server,
        epigraph_mcp::tools::alternative_sets::SuggestAlternativeSetsParams {
            target_claim_id: Some(t.to_string()),
            min_pair_strength: 0.0,
            exclude_settled: true,
            surface_reconsiderations: false,
        },
    ).await.expect("tool call ok");

    let payload = common::first_text(&resp);
    let candidates = serde_json::from_str::<serde_json::Value>(&payload).unwrap()
        ["candidates"].as_array().unwrap().clone();
    assert!(
        candidates.is_empty(),
        "alt-chosen member must suppress its pair (default exclude_settled=true), got {candidates:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn exclude_settled_false_surfaces_chosen_pair(pool: PgPool) {
    let server = common::build_test_server(pool.clone()).await;
    let t  = common::seed_claim(&pool, "Target").await;
    let a1 = common::seed_claim_with_truth(&pool, "A1", 0.7).await;
    let a2 = common::seed_claim_with_truth(&pool, "A2", 0.6).await;
    common::insert_edge(&pool, a1, t, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a2, t, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a1, a2, "claim", "claim", "contradicts").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['alt-chosen'] WHERE id = $1")
        .bind(a1).execute(&pool).await.unwrap();

    let resp = epigraph_mcp::tools::alternative_sets::suggest_alternative_sets(
        &server,
        epigraph_mcp::tools::alternative_sets::SuggestAlternativeSetsParams {
            target_claim_id: Some(t.to_string()),
            min_pair_strength: 0.0,
            exclude_settled: false,
            surface_reconsiderations: false,
        },
    ).await.expect("tool call ok");

    let payload = common::first_text(&resp);
    let candidates = serde_json::from_str::<serde_json::Value>(&payload).unwrap()
        ["candidates"].as_array().unwrap().clone();
    assert_eq!(
        candidates.len(), 1,
        "exclude_settled=false should return the pair regardless of labels, got {candidates:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn surface_reconsiderations_yields_rejected_with_stronger_rival(pool: PgPool) {
    let server = common::build_test_server(pool.clone()).await;
    let t  = common::seed_claim(&pool, "Target").await;
    let a1 = common::seed_claim_with_truth(&pool, "A1-rejected", 0.3).await;
    let a2 = common::seed_claim_with_truth(&pool, "A2-rival", 0.8).await;
    common::insert_edge(&pool, a1, t, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a2, t, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a1, a2, "claim", "claim", "contradicts").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['alt-rejected'] WHERE id = $1")
        .bind(a1).execute(&pool).await.unwrap();

    let resp = epigraph_mcp::tools::alternative_sets::suggest_alternative_sets(
        &server,
        epigraph_mcp::tools::alternative_sets::SuggestAlternativeSetsParams {
            target_claim_id: Some(t.to_string()),
            min_pair_strength: 0.3,   // BetP gap 0.5 must exceed this
            exclude_settled: true,
            surface_reconsiderations: true,
        },
    ).await.expect("tool call ok");

    let payload = common::first_text(&resp);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let candidates = parsed["candidates"].as_array().unwrap();
    assert_eq!(
        candidates.len(), 1,
        "rejected-with-stronger-rival pair should surface, got {candidates:?}"
    );
    let reason = candidates[0]["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("reconsider"),
        "reconsideration pair must have 'reconsider' reason prefix, got: {reason}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn surface_reconsiderations_skips_when_gap_too_small(pool: PgPool) {
    let server = common::build_test_server(pool.clone()).await;
    let t  = common::seed_claim(&pool, "Target").await;
    let a1 = common::seed_claim_with_truth(&pool, "A1-rejected", 0.6).await;
    let a2 = common::seed_claim_with_truth(&pool, "A2-only-slightly-better", 0.7).await;
    common::insert_edge(&pool, a1, t, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a2, t, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a1, a2, "claim", "claim", "contradicts").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['alt-rejected'] WHERE id = $1")
        .bind(a1).execute(&pool).await.unwrap();

    let resp = epigraph_mcp::tools::alternative_sets::suggest_alternative_sets(
        &server,
        epigraph_mcp::tools::alternative_sets::SuggestAlternativeSetsParams {
            target_claim_id: Some(t.to_string()),
            min_pair_strength: 0.5,   // gap of 0.1 does NOT exceed this threshold
            exclude_settled: true,
            surface_reconsiderations: true,
        },
    ).await.expect("tool call ok");

    let payload = common::first_text(&resp);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let candidates = parsed["candidates"].as_array().unwrap();
    assert!(
        candidates.is_empty(),
        "gap below min_pair_strength must not surface reconsideration, got {candidates:?}"
    );
}
```

- [ ] **Step 3: Update existing tests to pass explicit defaults**

The two tests from PR #187 (`suggest_returns_only_contradicts_pair` and `suggest_skips_pairs_with_existing_alternative_of`) construct `SuggestAlternativeSetsParams` literally. They will fail to compile after the new fields land unless they include defaults or use `..Default::default()`.

Search for those tests:

```bash
grep -n "SuggestAlternativeSetsParams {" crates/epigraph-mcp/tests/suggest_alternative_sets.rs
```

For each constructor missing the new fields, add `exclude_settled: false, surface_reconsiderations: false,` (preserves their original behavior — they tested unlabelled seeds). Alternatively, add `#[derive(Default)]` to the params struct and use `..Default::default()` in tests.

Simpler: add the explicit fields:

```rust
epigraph_mcp::tools::alternative_sets::SuggestAlternativeSetsParams {
    target_claim_id: Some(t.to_string()),
    min_pair_strength: 0.0,
    exclude_settled: false,
    surface_reconsiderations: false,
}
```

- [ ] **Step 4: Run all suggest_alternative_sets tests**

```bash
DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test' \
  cargo test -p epigraph-mcp --test suggest_alternative_sets -- --nocapture
```

Expected: 6 tests pass (2 original + 4 new).

- [ ] **Step 5: Joint commit Tasks 3 + 4**

```bash
git add crates/epigraph-mcp/src/tools/alternative_sets.rs \
        crates/epigraph-mcp/tests/suggest_alternative_sets.rs
git commit -m "feat(mcp): suggest_alternative_sets respects alt-set lifecycle labels

Two new optional params:
- exclude_settled (default true): drops pairs where any member is alt-chosen
  or alt-rejected, unless surface_reconsiderations overrides.
- surface_reconsiderations (default false): surfaces pairs where one member
  is alt-rejected and the BetP gap to its rival meets min_pair_strength —
  candidates for reconsideration.

The reason string for reconsideration pairs prefixes 'reconsider:' and
includes both BetPs."
```

---

### Task 5: File backlog claims (B) and (C) via MCP

**Files:** none modified in the repo. This task runs the `mcp__epigraph__memorize` tool to file backlog claims with their promotion triggers.

- [ ] **Step 1: File backlog item (B) — Decision-as-claim primitive**

Call `mcp__epigraph__memorize` with:

```python
mcp__epigraph__memorize(
    content=(
        "BACKLOG (alt-set-extension B): Decision-as-claim primitive.\n\n"
        "Promotion triggers — develop when ANY become true:\n"
        "1. Three or more reopens on a single alt-set (label thrashing).\n"
        "2. Multi-dimensional scoring (cost/time/risk independent of BetP) needed for ranking.\n"
        "3. A claim needs different states in two alt-sets it appears in (per-set state).\n\n"
        "Sketch: add Decision claim (label ['decision']) representing the choice point. "
        "Edges decides_among → claim from Decision to each alt-set member with edge properties "
        "{chosen, rejected_at, deferred_at, score}. Reopen = new edge to new candidate, old "
        "chosen=true becomes chosen=false with superseded_at.\n\n"
        "Depends on: spec at docs/superpowers/specs/2026-05-27-alt-set-lifecycle-design.md (A.1 + A.3 shipped first)."
    ),
    labels=["backlog", "alt-set-extension"],
)
```

- [ ] **Step 2: File backlog item (C) — Goal-decomposition tree primitive**

```python
mcp__epigraph__memorize(
    content=(
        "BACKLOG (alt-set-extension C): Goal-decomposition tree primitive.\n\n"
        "Promotion triggers — develop when ANY become true:\n"
        "1. WRHQ / Praxis / EpiClaw consumer requires multi-step pathway planning with sub-step "
        "   decomposition AND alt-set lifecycle on sub-pathways.\n"
        "2. A single Goal claim has > 5 candidate pathways each with own decomposes_to chains.\n"
        "3. The existing hierarchical-workflow primitive (store_workflow, add_step) is requested "
        "   to support alternative branches at any step.\n\n"
        "Sketch: add 'goal' label. Pathway claims supports → Goal with alternative_of linking "
        "competing pathways. Each pathway has its own decomposes_to sub-step chain. Lifecycle "
        "state (A.1 labels from this spec) applies to the pathway claim; sub-steps inherit "
        "operational state from their parent. Combines with (B) by making the Goal the implicit "
        "decision-point claim.\n\n"
        "Depends on: spec at docs/superpowers/specs/2026-05-27-alt-set-lifecycle-design.md, "
        "backlog (B) Decision-as-claim primitive (preferable to ship first)."
    ),
    labels=["backlog", "alt-set-extension"],
)
```

- [ ] **Step 3: Verify both claims landed**

Call `mcp__epigraph__query_claims_by_label(labels=["alt-set-extension"], exclude_labels=["resolved"], current_only=True)` and confirm both new claim IDs appear with content starting `BACKLOG (alt-set-extension B):` and `BACKLOG (alt-set-extension C):`.

Capture the two claim IDs returned by `memorize` (they appear in the tool response) for the PR body.

- [ ] **Step 4: No git commit needed**

The backlog filings live in EpiGraph, not in the repo. The PR body's "Backlog filings" section references them by UUID. Move on to Task 6.

---

### Task 6: Workspace verification

**Files:** none modified — verification only.

- [ ] **Step 1: Per-crate check and tests covering this branch's surfaces**

```bash
cd /home/jeremy/epigraph
export DATABASE_URL='postgres://epigraph:epigraph@localhost/epigraph_db_repo_test'

SQLX_OFFLINE=true cargo check --workspace
cargo fmt --all -- --check
cargo clippy -p epigraph-api --lib -- -D warnings
cargo clippy -p epigraph-mcp --lib -- -D warnings

# Branch-touched tests:
cargo test -p epigraph-api --test alt_set_decisions_view_test -- --nocapture
cargo test -p epigraph-mcp --test suggest_alternative_sets -- --nocapture
```

Expected: all clean, both test files pass.

- [ ] **Step 2: No-regression spot-check on PR #187's CDST integration**

Confirm the alt-set CDST integration test from PR #187 still passes (belief semantics must be label-agnostic):

```bash
cargo test -p epigraph-engine --test alt_set_cdst_integration -- --nocapture
```

Expected: PASS, same BetP shift values as PR #187 (~0.970 → 0.911 with alt-set wiring).

- [ ] **Step 3: Confirm worktree clean**

```bash
git status -sb
```

- [ ] **Step 4: Commit any fmt fallout**

If `cargo fmt --check` reported diffs:

```bash
cargo fmt --all
git add -A
git commit -m "chore: cargo fmt after alt-set lifecycle work"
```

---

### Task 7: Push branch and open PR

- [ ] **Step 1: Push**

```bash
cd /home/jeremy/epigraph
git push -u origin feat/alt-set-lifecycle
```

- [ ] **Step 2: Open PR**

Substitute the two backlog claim IDs from Task 5 for `<B_CLAIM_ID>` and `<C_CLAIM_ID>`.

```bash
gh pr create --repo epigraph-io/epigraph \
  --title "feat: alt-set lifecycle labels (alt-chosen / alt-rejected / alt-deferred)" \
  --body "$(cat <<'EOF'
## Summary
- Three reserved labels (`alt-chosen`, `alt-rejected`, `alt-deferred`) on alt-set members — operational lifecycle without new claim or edge types.
- Optional `properties.alt_state_meta` JSONB carries transitioned_at, transitioned_by, rationale, multi-dim score.
- New `alt_set_decisions` SQL view (migration 043) joins `alternative_set` + claim labels/properties for one-shot decision queries.
- Two new optional params on `mcp__epigraph__suggest_alternative_sets`:
  - `exclude_settled` (default true) — drops pairs where any member is `alt-chosen` or `alt-rejected`.
  - `surface_reconsiderations` (default false) — surfaces rejected-with-stronger-rival pairs as reconsideration candidates.
- Backlog items (B) Decision-as-claim and (C) Goal-decomposition tree filed via `mcp__epigraph__memorize` with explicit promotion triggers (see `docs/superpowers/specs/2026-05-27-alt-set-lifecycle-design.md` § Backlog filings).
  - (B): claim `<B_CLAIM_ID>`
  - (C): claim `<C_CLAIM_ID>`

## Why
PR #187 shipped the *math* for alt-set combination (max-Pl reduction in CDST). This PR ships the *operational lifecycle* needed for developmental-pathway planning — choose a pathway, defer alternatives, reopen a previously-rejected pathway when a stronger one appears. Belief semantics are unchanged: CDST still applies max-Pl across all members regardless of label. Lifecycle is operational, not epistemic.

The original brainstorm considered a richer Decision-as-claim primitive and a Goal-decomposition tree primitive. Both were rejected for this PR (YAGNI — no concrete consumer yet) and filed as backlog with promotion triggers that name the specific conditions that would justify them.

See `docs/superpowers/specs/2026-05-27-alt-set-lifecycle-design.md` for the full design rationale.

## Test plan
- [x] `cargo test -p epigraph-api --test alt_set_decisions_view_test` — view classifies by label priority and surfaces alt_state_meta
- [x] `cargo test -p epigraph-mcp --test suggest_alternative_sets` — 6 tests covering default-exclude, opt-out, reconsideration surfacing, and gap-threshold gating
- [x] `cargo test -p epigraph-engine --test alt_set_cdst_integration` — PR #187's CDST regression still green (belief semantics are label-agnostic)
- [x] `SQLX_OFFLINE=true cargo check --workspace` clean
- [x] `cargo fmt --all -- --check` clean
- [x] Per-crate `cargo clippy --lib -- -D warnings` clean for epigraph-api / epigraph-mcp

## Migration note
Migration `043` lands cleanly after `041` (PR #185) and `042` (PR #187), both merged to main.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Verify PR exists**

```bash
gh pr view --repo epigraph-io/epigraph --json url,number,title
```

---

## Done

- Three reserved labels carry operational lifecycle state on alt-set members.
- `alt_set_decisions` view exposes state + metadata in one query.
- `suggest_alternative_sets` respects settled state and can surface reconsiderations.
- Backlog items (B) and (C) recorded with promotion triggers.
- CDST belief reasoning unchanged.
