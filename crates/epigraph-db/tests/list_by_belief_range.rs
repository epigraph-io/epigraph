//! `ClaimRepository::list_by_belief_range` — the `query_claims` range read.
//!
//! Four properties, each pinned by one test:
//!
//! 1. Backlog `5a55a48e`: `query_claims(min_truth=0, max_truth=0.75)` returned
//!    an empty list even though matching claims existed, because the handler
//!    fetched the first `limit` rows and filtered *in Rust, after* the `LIMIT`.
//!    The range is filtered in SQL *before* `LIMIT`.
//! 2. GitHub #395 (G10): the range is on the BELIEF SCORE (DS pignistic when the
//!    claim has DS state, else `truth_value`), not on the stale authored
//!    `truth_value` — so a refuted claim is in a low-range queue and a
//!    vindicated one is not.
//! 3. Deterministic paging: ties on `created_at` are broken by `id`, so `offset`
//!    neither repeats nor skips a row.
//! 4. Backlog `31e7b727`: verbatim document-spine nodes (`properties.level`
//!    0/1/2: thesis, section heading, paragraph — "Keywords:" lists, captions,
//!    transcript turns) filled the newest-first `max_truth=0.4` page before the
//!    assessment agent could discard them. `exclude_spine` drops EVERY claim at
//!    level 0-2 in SQL *before* `LIMIT` (workflow thesis/phase/step nodes
//!    included: the predicate reads `level` alone), keeps atoms (level 3) and
//!    unleveled claims, is off by default, and binds correctly for a bind-less
//!    (bypass) viewer as well as a scoped one.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

/// Insert a claim with an explicit id, `truth_value` and `created_at`.
async fn seed_claim_with_id(pool: &PgPool, id: Uuid, agent_id: Uuid, truth: f64, created_at: &str) {
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6::timestamptz)",
    )
    .bind(id)
    .bind(format!("test claim {id}"))
    .bind(hash)
    .bind(truth)
    .bind(agent_id)
    .bind(created_at)
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, truth: f64, created_at: &str) -> Uuid {
    let id = Uuid::new_v4();
    seed_claim_with_id(pool, id, agent_id, truth, created_at).await;
    id
}

/// Give a claim a DS cache, as a recompute would write it.
async fn set_ds(pool: &PgPool, id: Uuid, belief: f64, plausibility: f64, betp: f64) {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(belief)
    .bind(plausibility)
    .bind(betp)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn range_filter_finds_matches_outside_recent_window(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // 25 RECENT claims with high truth (0.95) — these crowd out the top-`limit`
    // most-recent rows.
    for i in 0..25 {
        let ts = format!("2026-05-29T12:00:{:02}Z", i);
        seed_claim(&pool, agent, 0.95, &ts).await;
    }
    // One OLD claim with low truth (0.50) — the only one in [0, 0.75], but it
    // is the *oldest* row, so a fetch-recent-then-filter strategy never sees it.
    seed_claim(&pool, agent, 0.50, "2026-01-01T00:00:00Z").await;

    let results =
        ClaimRepository::list_by_belief_range(&pool, &viewer, 0.0, 0.75, None, 20, 0, false)
            .await
            .unwrap();

    // The low-truth claim must be returned despite being outside the 20 newest.
    assert_eq!(
        results.len(),
        1,
        "expected exactly the one claim in [0,0.75], got {}",
        results.len()
    );
    let (claim, score) = &results[0];
    assert!(
        (0.0..=0.75).contains(score),
        "returned claim score {score} outside requested range"
    );
    // No DS state: the score IS the authored truth_value.
    assert!((score - claim.truth_value.value()).abs() < 1e-12);

    // And a high-range query still excludes it.
    let high = ClaimRepository::list_by_belief_range(&pool, &viewer, 0.9, 1.0, None, 20, 0, false)
        .await
        .unwrap();
    assert!(
        high.iter().all(|(_, s)| *s >= 0.9),
        "high-range query leaked a sub-0.9 claim"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_range_is_on_the_belief_score_not_the_stale_truth_value(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // Refuted by epistemic evidence: authored 0.78, BetP 0.18.
    let refuted = seed_claim(&pool, agent, 0.78, "2026-03-01T00:00:00Z").await;
    set_ds(&pool, refuted, 0.10, 0.25, 0.18).await;
    // Vindicated: authored 0.30, BetP 0.90.
    let vindicated = seed_claim(&pool, agent, 0.30, "2026-03-02T00:00:00Z").await;
    set_ds(&pool, vindicated, 0.85, 0.95, 0.90).await;
    // Half-written DS row (belief without plausibility): the guard falls back
    // to truth_value, exactly as `effective_belief_batch` does.
    let half = seed_claim(&pool, agent, 0.35, "2026-03-03T00:00:00Z").await;
    sqlx::query("UPDATE claims SET belief = 0.99, pignistic_prob = 0.99 WHERE id = $1")
        .bind(half)
        .execute(&pool)
        .await
        .unwrap();

    let low: Vec<(Uuid, f64)> =
        ClaimRepository::list_by_belief_range(&pool, &viewer, 0.0, 0.4, None, 20, 0, false)
            .await
            .unwrap()
            .into_iter()
            .map(|(c, s)| (c.id.as_uuid(), s))
            .collect();
    let low_ids: Vec<Uuid> = low.iter().map(|(id, _)| *id).collect();
    assert!(
        low_ids.contains(&refuted),
        "the refuted claim (BetP 0.18, truth 0.78) is missing from max=0.4: {low:?}"
    );
    assert!(
        !low_ids.contains(&vindicated),
        "the vindicated claim (BetP 0.90, truth 0.30) leaked into max=0.4: {low:?}"
    );
    assert!(
        low_ids.contains(&half),
        "half-written DS row must fall back: {low:?}"
    );
    let refuted_score = low.iter().find(|(id, _)| *id == refuted).unwrap().1;
    assert!(
        (refuted_score - 0.18).abs() < 1e-12,
        "projected {refuted_score}"
    );

    // The SAME score `effective_belief_batch` (recall's min_truth gate) reads.
    let batch =
        ClaimRepository::effective_belief_batch(&pool, &viewer, &[refuted, vindicated, half])
            .await
            .unwrap();
    for (id, s) in &low {
        assert!(
            (batch[id] - s).abs() < 1e-12,
            "{id}: range {s} vs batch {}",
            batch[id]
        );
    }

    let high = ClaimRepository::list_by_belief_range(&pool, &viewer, 0.8, 1.0, None, 20, 0, false)
        .await
        .unwrap();
    assert!(high.iter().any(|(c, _)| c.id.as_uuid() == vindicated));
    assert!(!high.iter().any(|(c, _)| c.id.as_uuid() == refuted));
}

#[sqlx::test(migrations = "../../migrations")]
async fn paging_breaks_created_at_ties_by_id(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // Three claims sharing one created_at, INSERTED in descending id order so a
    // tie left to physical order comes back high-id first.
    let ts = "2026-04-01T00:00:00Z";
    let mut ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
    ids.sort();
    for id in ids.iter().rev() {
        seed_claim_with_id(&pool, *id, agent, 0.5, ts).await;
    }

    let mut paged = Vec::new();
    for offset in 0..3 {
        let page =
            ClaimRepository::list_by_belief_range(&pool, &viewer, 0.0, 1.0, None, 1, offset, false)
                .await
                .unwrap();
        assert_eq!(page.len(), 1, "offset {offset}");
        paged.push(page[0].0.id.as_uuid());
    }
    assert_eq!(
        paged, ids,
        "ties on created_at must page in id order, every row exactly once"
    );
}

/// Set `claims.properties` to exactly `props` (a JSON object literal).
async fn set_properties(pool: &PgPool, id: Uuid, props: &str) {
    sqlx::query("UPDATE claims SET properties = $2::jsonb WHERE id = $1")
        .bind(id)
        .bind(props)
        .execute(pool)
        .await
        .unwrap();
}

fn ids(page: &[(epigraph_core::Claim, f64)]) -> Vec<Uuid> {
    page.iter().map(|(c, _)| c.id.as_uuid()).collect()
}

/// Backlog `31e7b727`. The production shape: the newest row in the low-truth
/// window is a level-2 spine paragraph (a "Keywords:" list the extractor scored
/// 0.375), and with `limit = 1` it consumes the only slot, so the older atom
/// the assessment agent could actually enrich is never reached. Filtering
/// after the page is fetched cannot win the slot back; the exclusion has to sit
/// before `LIMIT`.
#[sqlx::test(migrations = "../../migrations")]
async fn exclude_spine_drops_paragraphs_before_limit_so_an_older_atom_is_reached(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // Newest first: para (level 2), atom (level 3), then the older rows.
    let para = seed_claim(&pool, agent, 0.375, "2026-09-02T18:40:27Z").await;
    set_properties(
        &pool,
        para,
        r#"{"level": 2, "spine_text_kind": "paragraph"}"#,
    )
    .await;
    // A workflow step (builder / evolve_step) also sits at level 2. It is newer
    // than the atom, so the `limit = 1` slot below pins it as excluded too.
    let wf_step = seed_claim(&pool, agent, 0.30, "2026-09-01T12:00:00Z").await;
    set_properties(
        &pool,
        wf_step,
        r#"{"level": 2, "source_type": "workflow", "kind": "workflow_step"}"#,
    )
    .await;
    let atom = seed_claim(&pool, agent, 0.30, "2026-09-01T00:00:00Z").await;
    set_properties(&pool, atom, r#"{"level": 3}"#).await;
    // Thesis (level 0) and section heading (level 1) are spine too.
    let thesis = seed_claim(&pool, agent, 0.30, "2026-08-20T00:00:00Z").await;
    set_properties(&pool, thesis, r#"{"level": 0}"#).await;
    let section = seed_claim(&pool, agent, 0.30, "2026-08-15T00:00:00Z").await;
    set_properties(&pool, section, r#"{"level": 1}"#).await;
    // A claim from submit_claim / memorize carries no level at all.
    let plain = seed_claim(&pool, agent, 0.30, "2026-08-01T00:00:00Z").await;

    // ---- The single slot goes to the atom, not the newer paragraph ----
    let one =
        ClaimRepository::list_by_belief_range(&pool, &viewer, 0.0, 0.4, Some(true), 1, 0, true)
            .await
            .unwrap();
    assert_eq!(
        ids(&one),
        vec![atom],
        "exclude_spine=true with limit=1 must skip the newer level-2 paragraph \
         ({para}) and level-2 workflow step ({wf_step}) in SQL and return the \
         older level-3 atom"
    );

    // ---- Default unchanged: off means the paragraph still takes the slot ----
    let off =
        ClaimRepository::list_by_belief_range(&pool, &viewer, 0.0, 0.4, Some(true), 1, 0, false)
            .await
            .unwrap();
    assert_eq!(
        ids(&off),
        vec![para],
        "exclude_spine=false must leave the page exactly as before"
    );

    // ---- Every spine level goes; atoms and unleveled claims stay ----
    let wide =
        ClaimRepository::list_by_belief_range(&pool, &viewer, 0.0, 0.4, Some(true), 10, 0, true)
            .await
            .unwrap();
    assert_eq!(
        ids(&wide),
        vec![atom, plain],
        "exclude_spine=true must drop levels 0, 1 and 2 (thesis {thesis}, section \
         {section}, paragraph {para}, workflow step {wf_step}) and keep the atom \
         and the unleveled claim, newest first"
    );

    // ---- Same filter through a viewer with a NON-EMPTY group set ----
    // `public_viewer` above is Scoped with an EMPTY group set: it still binds
    // the group array, so it binds all seven values. This section varies the
    // group CONTENT only (a real membership); it says nothing about the bind
    // COUNT, which the bypass section below pins.
    let (member, _group) = fixture::seed_agent_with_group(&pool, "u056").await;
    let grouped = epigraph_db::visibility::Viewer::resolve(&pool, member)
        .await
        .unwrap();
    let wide_grouped =
        ClaimRepository::list_by_belief_range(&pool, &grouped, 0.0, 0.4, Some(true), 10, 0, true)
            .await
            .unwrap();
    assert_eq!(ids(&wide_grouped), vec![atom, plain]);

    // ---- A bind-less viewer: the group bind must stay LAST ----
    // A bypass viewer (and an elevated one: an MCP `query_claims` caller with a
    // live elevation, `tools/viewer.rs`) returns `group_bind() == None`, so the
    // statement carries six binds, not
    // seven. With `exclude_spine` at `$6` and the conditional group bind at
    // `$7`, that is exactly right; were the group spliced at `$6` and the flag
    // moved to `$7`, this call would be one bind short and fail.
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let wide_bypass =
        ClaimRepository::list_by_belief_range(&pool, &bypass, 0.0, 0.4, Some(true), 10, 0, true)
            .await
            .expect("a bind-less viewer must bind exclude_spine at $6 with no group bind");
    assert_eq!(
        ids(&wide_bypass),
        vec![atom, plain],
        "a bypass viewer sees every row, so exactly [atom, plain] also pins that no \
         spine or workflow level-0/1/2 row leaks through the bind-less path"
    );
}
