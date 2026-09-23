//! Integration tests for the `claim_themes` READ path
//! (`ClaimThemeRepository::list_summaries` / `count_summaries` /
//! `get_summary` / `find_by_label` / `member_claim_ids`).
//!
//! Backlog `c40689c9-a6c0-4c90-adfb-cf52e8a6b917`: the theme layer had no
//! reader, so "what topics does this graph cover" could only be answered by
//! running `theme_cluster`, which wipes and rebuilds.
//!
//! ## Why these are not tautologies
//!
//! The obvious implementation of a theme reader is a thin wrapper over the
//! pre-existing `ClaimThemeRepository::list`, which returns the denormalised
//! `claim_themes.claim_count` column. Every fixture below seeds that column
//! with a value that is DELIBERATELY WRONG relative to the actual
//! `claims.theme_id` assignments — which is exactly what production looks
//! like, because `assign_claim` / `bulk_assign` / `unassign_claim` write
//! `claims.theme_id` and never update `claim_count`. A `list`-wrapper passes
//! nothing here.
//!
//! Schema notes (mirrors `claim_search_hybrid.rs`): seed an `agents` row first
//! (FK + edge-validation trigger); `content_hash bytea NOT NULL` with a
//! `(content_hash, agent_id)` UNIQUE index → use distinct hashes.

mod viewer_fixture;

use epigraph_db::ClaimThemeRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("bb".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

/// Insert a theme with an explicit — and deliberately stale —
/// `claim_count`, plus an optional centroid so `centroid_dim` has something
/// to derive from.
async fn seed_theme(pool: &PgPool, label: &str, stored_count: i32, dim: Option<u32>) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description, claim_count) \
         VALUES ($1, 'seeded by claim_theme_reads', $2) RETURNING id",
    )
    .bind(label)
    .bind(stored_count)
    .fetch_one(pool)
    .await
    .expect("insert theme");

    if let Some(d) = dim {
        let vec_literal = format!("[{}]", vec!["0.1"; d as usize].join(","));
        let col = if d == 3072 {
            "centroid_3072"
        } else {
            "centroid"
        };
        sqlx::query(&format!(
            "UPDATE claim_themes SET {col} = $2::vector WHERE id = $1"
        ))
        .bind(id)
        .bind(&vec_literal)
        .execute(pool)
        .await
        .expect("set centroid");
    }
    id
}

fn hash_for(id: Uuid) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[..16].copy_from_slice(id.as_bytes());
    h
}

/// Insert a claim already assigned to `theme_id`, WITHOUT touching
/// `claim_themes.claim_count` — the production behaviour of
/// `assign_claim` / `bulk_assign`.
async fn seed_member(
    pool: &PgPool,
    agent: Uuid,
    theme_id: Uuid,
    content: &str,
    is_current: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, theme_id) \
         VALUES ($1, $2, $3, $4, 0.7, $5, $6)",
    )
    .bind(id)
    .bind(content)
    .bind(hash_for(id))
    .bind(agent)
    .bind(is_current)
    .bind(theme_id)
    .execute(pool)
    .await
    .expect("insert member claim");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn summary_reports_live_member_count_not_the_stale_column(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    // Stored count says 0. Three real members exist. Production drifts this
    // way because only `update_count` maintains the column.
    let theme = seed_theme(&pool, "drift-00", 0, Some(1536)).await;
    for i in 0..3 {
        seed_member(&pool, agent, theme, &format!("drifted member {i}"), true).await;
    }

    let summary = ClaimThemeRepository::get_summary(&pool, &viewer, theme)
        .await
        .expect("get_summary")
        .expect("theme exists");

    assert_eq!(
        summary.member_count, 3,
        "member_count must be the live COUNT(*) over claims.theme_id, not claim_themes.claim_count"
    );
    assert_eq!(
        summary.stored_claim_count, 0,
        "the stale denormalised column must still be reported verbatim so drift is visible"
    );
    assert_eq!(
        summary.centroid_dim,
        Some(1536),
        "centroid_dim is derived from which centroid column is populated"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn retired_members_are_excluded_from_count_and_page(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let theme = seed_theme(&pool, "retired-00", 99, None).await;
    let live = seed_member(&pool, agent, theme, "live member", true).await;
    let retired = seed_member(&pool, agent, theme, "retired member", false).await;

    let summary = ClaimThemeRepository::get_summary(&pool, &viewer, theme)
        .await
        .expect("get_summary")
        .expect("theme exists");
    assert_eq!(
        summary.member_count, 1,
        "only is_current members count: a retired claim is unreachable by recall (migration 052 \
         nulls its embedding), so counting it would overstate what the theme can return"
    );
    assert_eq!(
        summary.centroid_dim, None,
        "a theme with no centroid at all must report None, not a fabricated 1536"
    );

    let members = ClaimThemeRepository::member_claim_ids(&pool, &viewer, theme, 50, 0)
        .await
        .expect("member page");
    let ids: Vec<Uuid> = members.iter().map(|m| m.claim_id).collect();
    assert_eq!(ids, vec![live], "page must agree with the count");
    assert!(
        !ids.contains(&retired),
        "retired member leaked into the member page"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn member_paging_walks_the_theme_to_exhaustion_without_repeats(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let theme = seed_theme(&pool, "paged-00", 0, None).await;
    let mut expected = Vec::new();
    for i in 0..7 {
        expected.push(seed_member(&pool, agent, theme, &format!("page member {i}"), true).await);
    }

    // Collapse every member onto ONE created_at. Without this the fixture
    // would pass over an `ORDER BY created_at` that has no `id` tiebreaker,
    // because distinct timestamps make the order total by accident. Bulk
    // ingest genuinely writes many claims inside the same instant, so the tied
    // case is the production case — and under a non-total ORDER BY, Postgres
    // is free to return a different permutation per page, which duplicates
    // some members and drops others.
    sqlx::query("UPDATE claims SET created_at = '2025-01-01T00:00:00Z' WHERE theme_id = $1")
        .bind(theme)
        .execute(&pool)
        .await
        .expect("collapse timestamps");

    // With created_at tied across all seven, `created_at ASC, id ASC` reduces
    // to `id ASC` — a total order that does NOT coincide with insertion order
    // (the ids are random v4 UUIDs). Asserting the exact sequence is therefore
    // a real test of the tiebreaker, not just of set membership.
    expected.sort();

    let mut seen = Vec::new();
    let mut offset = 0i64;
    loop {
        let page = ClaimThemeRepository::member_claim_ids(&pool, &viewer, theme, 3, offset)
            .await
            .expect("member page");
        if page.is_empty() {
            break;
        }
        offset += page.len() as i64;
        seen.extend(page.into_iter().map(|m| m.claim_id));
        assert!(offset <= 20, "paging failed to terminate");
    }
    assert_eq!(
        seen, expected,
        "a limit/offset walk must yield every member exactly once, in `created_at ASC, id ASC` \
         order; a non-total ORDER BY lets Postgres permute tied rows between pages, which \
         duplicates some members and drops others"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_summaries_filters_by_prefix_and_orders_by_live_count(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    // `small` carries a huge stale claim_count and ONE real member; `big`
    // carries a stale zero and TWO. Ordering by the stored column would put
    // `small` first — ordering by live membership puts `big` first.
    let small = seed_theme(&pool, "px-small", 9999, None).await;
    let big = seed_theme(&pool, "px-big", 0, None).await;
    let other = seed_theme(&pool, "zz-other", 0, None).await;

    seed_member(&pool, agent, small, "small m0", true).await;
    seed_member(&pool, agent, big, "big m0", true).await;
    seed_member(&pool, agent, big, "big m1", true).await;
    seed_member(&pool, agent, other, "other m0", true).await;

    let page = ClaimThemeRepository::list_summaries(&pool, &viewer, Some("px-"), 50, 0)
        .await
        .expect("list_summaries");
    let ids: Vec<Uuid> = page.iter().map(|t| t.id).collect();
    assert_eq!(
        ids,
        vec![big, small],
        "label_prefix must exclude zz-other, and ordering must follow live member_count \
         (big=2) over the stale claim_count (small=9999)"
    );

    let total = ClaimThemeRepository::count_summaries(&pool, Some("px-"))
        .await
        .expect("count_summaries");
    assert_eq!(total, 2, "count must apply the same prefix predicate");

    let unfiltered = ClaimThemeRepository::count_summaries(&pool, None)
        .await
        .expect("count_summaries unfiltered");
    assert_eq!(unfiltered, 3, "None must mean no filter");

    let blank = ClaimThemeRepository::count_summaries(&pool, Some("   "))
        .await
        .expect("count_summaries blank");
    assert_eq!(
        blank, 3,
        "a whitespace-only prefix is normalised to no filter"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_by_label_surfaces_duplicate_labels_instead_of_picking_one(pool: PgPool) {
    // `claim_themes` has no UNIQUE(label); `theme_cluster(wipe_first=false)`
    // produces exactly this state. A resolver that returned Option would
    // silently pick one of two distinct themes.
    let a = seed_theme(&pool, "auto-00", 0, None).await;
    let b = seed_theme(&pool, "auto-00", 0, None).await;

    let mut found = ClaimThemeRepository::find_by_label(&pool, "auto-00")
        .await
        .expect("find_by_label");
    found.sort();
    let mut expected = vec![a, b];
    expected.sort();
    assert_eq!(
        found, expected,
        "both duplicate-label themes must be returned"
    );

    let none = ClaimThemeRepository::find_by_label(&pool, "auto-nonexistent")
        .await
        .expect("find_by_label miss");
    assert!(none.is_empty(), "a miss is an empty Vec, not an error");
}
