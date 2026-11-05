//! Integration tests for the `claim_themes` READ path
//! (`ClaimThemeRepository::list_summaries` / `count_summaries` /
//! `get_summary` / `find_by_label` / `member_claim_ids` / `overview_page`).
//!
//! `overview_page` (backlog 57917c13) backs `GET /api/v1/graph/themes/overview`:
//! live, viewer-scoped member counts, themes with no readable member absent,
//! keyset-paged. Its arms are at the end of this file.
//!
//! Backlog `c40689c9-a6c0-4c90-adfb-cf52e8a6b917`: the theme layer had no
//! reader, so "what topics does this graph cover" could only be answered by
//! running `theme_cluster`, which then wiped and rebuilt the set by default
//! (since backlog 5abe23de its default is an additive run, and a wipe needs
//! `claims:admin` and the canonical `"auto"` prefix).
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

use epigraph_db::repos::{ThemeOverviewCursor, ThemeOverviewPage};
use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimThemeRepository;
use sqlx::{Executor, PgPool};
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
    // `claim_themes` has no UNIQUE(label); the retired k-means tool's additive
    // runs (`theme_cluster(wipe_first=false)`) left exactly this state. A resolver that returned Option would
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

// ---- overview_page (backlog 57917c13) -----------------------------------------

/// A CURRENT claim assigned to `theme_id`, private to `group`
/// (`visibility = 'group'`), the shape of `viewer_fixture::seed_group_claim`
/// plus the theme assignment.
async fn seed_group_member(
    pool: &PgPool,
    agent: Uuid,
    group: Uuid,
    theme_id: Uuid,
    content: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             theme_id, visibility, owner_group_id) \
         VALUES ($1, $2, $3, $4, 0.7, true, $5, 'group', $6)",
    )
    .bind(id)
    .bind(content)
    .bind(hash_for(id))
    .bind(agent)
    .bind(theme_id)
    .bind(group)
    .execute(pool)
    .await
    .expect("insert group-private member claim");
    let got: (String, Option<Uuid>) =
        sqlx::query_as("SELECT visibility, owner_group_id FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read the private member back");
    assert_eq!(
        got,
        ("group".to_string(), Some(group)),
        "CALIBRATION: the member must land group-private, or every 'the outsider \
         cannot see it' assertion below is vacuous"
    );
    id
}

/// `(id, member_count)` of a page, in page order.
fn pairs(page: &ThemeOverviewPage) -> Vec<(Uuid, i64)> {
    page.themes.iter().map(|t| (t.id, t.member_count)).collect()
}

/// `member_count DESC, id ASC`, the overview's order.
fn overview_order(v: &mut [(Uuid, i64)]) {
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
}

async fn overview(pool: &PgPool, viewer: &Viewer, limit: i64) -> ThemeOverviewPage {
    ClaimThemeRepository::overview_page(pool, viewer, None, limit)
        .await
        .expect("overview_page")
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_page_counts_live_current_members_not_the_stored_column(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let theme = seed_theme(&pool, "ov-live", 9999, None).await;
    for i in 0..3 {
        seed_member(&pool, agent, theme, &format!("ov live member {i}"), true).await;
    }
    seed_member(&pool, agent, theme, "ov retired member", false).await;
    // An unthemed claim must not be counted anywhere.
    let unthemed = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value) \
         VALUES ($1, 'ov unthemed', $2, $3, 0.7)",
    )
    .bind(unthemed)
    .bind(hash_for(unthemed))
    .bind(agent)
    .execute(&pool)
    .await
    .expect("insert unthemed claim");

    let page = overview(&pool, &viewer, 200).await;
    assert_eq!(
        pairs(&page),
        vec![(theme, 3)],
        "member_count is the live COUNT of CURRENT members, not the stored 9999 and \
         not counting the retired member"
    );
    assert_eq!(page.themes[0].label, "ov-live");
    assert_eq!(page.total, 1);
    assert_eq!(page.next, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_page_omits_themes_with_no_readable_member(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "ov-omit").await;
    let empty = seed_theme(&pool, "ov-empty", 40, None).await;
    let private = seed_theme(&pool, "ov-private", 40, None).await;
    let public = seed_theme(&pool, "ov-public", 0, None).await;
    seed_group_member(&pool, owner, group, private, "ov private member").await;
    seed_member(&pool, agent, public, "ov public member", true).await;

    let page = overview(&pool, &viewer, 200).await;
    let ids: Vec<Uuid> = page.themes.iter().map(|t| t.id).collect();
    assert_eq!(
        ids,
        vec![public],
        "a theme with no member (E) and one whose only member is private (P) are \
         absent, not zero"
    );
    assert!(!ids.contains(&empty) && !ids.contains(&private));
    assert_eq!(
        page.total, 1,
        "total counts only themes the viewer can read"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_page_counts_only_what_the_viewer_can_read(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let (member, group) = viewer_fixture::seed_agent_with_group(&pool, "ov-member").await;
    let (stranger, stranger_group) =
        viewer_fixture::seed_agent_with_group(&pool, "ov-stranger").await;
    assert_ne!(group, stranger_group, "two viewers in DIFFERENT groups");

    let q = seed_theme(&pool, "ov-q", 50, None).await;
    let p = seed_theme(&pool, "ov-p", 50, None).await;
    seed_member(&pool, agent, q, "ov q public", true).await;
    seed_group_member(&pool, member, group, q, "ov q private a").await;
    seed_group_member(&pool, member, group, q, "ov q private b").await;
    seed_group_member(&pool, member, group, p, "ov p private").await;

    let member_viewer = Viewer::resolve(&pool, member).await.expect("resolve");
    let stranger_viewer = Viewer::resolve(&pool, stranger).await.expect("resolve");

    // Calibration: the member arm is not vacuous.
    let seen = overview(&pool, &member_viewer, 200).await;
    assert_eq!(pairs(&seen), vec![(q, 3), (p, 1)]);
    assert_eq!(seen.total, 2);

    let hidden = overview(&pool, &stranger_viewer, 200).await;
    assert_eq!(
        pairs(&hidden),
        vec![(q, 1)],
        "the outsider counts only Q's public member and never sees P"
    );
    assert_eq!(hidden.total, 1, "the outsider's total does not count P");
    assert_eq!(hidden.next, None, "no cursor hints at a hidden row");

    // With limit 1 the outsider's walk is still one page with no cursor.
    let one = overview(&pool, &stranger_viewer, 1).await;
    assert_eq!(pairs(&one), vec![(q, 1)]);
    assert_eq!(one.next, None);
    assert_eq!(one.total, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_page_keyset_walk_is_complete_and_disjoint(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let mut expected: Vec<(Uuid, i64)> = Vec::new();
    for (i, n) in [3i64, 2, 2, 1, 1].into_iter().enumerate() {
        let theme = seed_theme(&pool, &format!("ov-walk-{i}"), 0, None).await;
        for k in 0..n {
            seed_member(&pool, agent, theme, &format!("ov walk {i} {k}"), true).await;
        }
        expected.push((theme, n));
    }
    // Random v4 ids, so the tie order is a real test of the `id ASC`
    // tiebreaker, not of insertion order.
    overview_order(&mut expected);

    let whole = overview(&pool, &viewer, 200).await;
    assert_eq!(pairs(&whole), expected);
    assert_eq!(whole.next, None);

    let mut walked: Vec<(Uuid, i64)> = Vec::new();
    let mut sizes = Vec::new();
    let mut after: Option<ThemeOverviewCursor> = None;
    for _ in 0..10 {
        let page = ClaimThemeRepository::overview_page(&pool, &viewer, after, 2)
            .await
            .expect("overview_page");
        assert_eq!(page.total, 5, "total is the same on every page");
        sizes.push(page.themes.len());
        walked.extend(pairs(&page));
        match page.next {
            Some(c) => {
                assert_eq!(
                    Some(c),
                    page.themes.last().map(ThemeOverviewCursor::of),
                    "next is the last row's position"
                );
                after = Some(c);
            }
            None => break,
        }
    }
    assert_eq!(
        sizes,
        vec![2, 2, 1],
        "next is None exactly on the last page"
    );
    assert_eq!(walked, expected, "the walk equals the single page");
    let mut ids: Vec<Uuid> = walked.iter().map(|(id, _)| *id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 5, "no theme twice");
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_page_past_the_end_keeps_total(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    for i in 0..2 {
        let theme = seed_theme(&pool, &format!("ov-end-{i}"), 0, None).await;
        seed_member(&pool, agent, theme, &format!("ov end {i}"), true).await;
    }
    let first = overview(&pool, &viewer, 200).await;
    assert_eq!(first.total, 2);

    let past = ClaimThemeRepository::overview_page(
        &pool,
        &viewer,
        Some(ThemeOverviewCursor {
            member_count: 1,
            id: Uuid::max(),
        }),
        200,
    )
    .await
    .expect("overview_page past the end");
    assert!(past.themes.is_empty());
    assert_eq!(past.next, None);
    assert_eq!(past.total, first.total, "total is present on an empty page");
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_page_never_exceeds_the_cap(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    for i in 0..205 {
        let theme = seed_theme(&pool, &format!("ov-cap-{i:03}"), 0, None).await;
        seed_member(&pool, agent, theme, &format!("ov cap {i}"), true).await;
    }
    let page = overview(&pool, &viewer, 10_000).await;
    assert_eq!(page.themes.len(), 200, "limit is clamped to 200");
    assert!(page.next.is_some(), "a cut page carries a cursor");
    assert_eq!(page.total, 205);

    let rest = ClaimThemeRepository::overview_page(&pool, &viewer, page.next, 10_000)
        .await
        .expect("second page");
    assert_eq!(rest.themes.len(), 5);
    assert_eq!(rest.next, None);

    // A non-positive limit is clamped to 1, not an error.
    let tiny = overview(&pool, &viewer, 0).await;
    assert_eq!(tiny.themes.len(), 1);
    assert!(tiny.next.is_some());
}

/// The POLICY half (mirror of `claims_query_scoped_read_policy.rs`): on a
/// `read_as`-stamped connection downgraded to `epigraph_app`, the member's own
/// private member is counted; on an UNSTAMPED downgraded connection the same
/// call with the same viewer does not count it. Proves the GUC stamp and the
/// in-query `$V` predicate agree, in both `SessionGucMode`s.
async fn overview_policy_half(pool: PgPool, mode: epigraph_db::SessionGucMode) {
    let agent = seed_agent(&pool).await;
    let (member, group) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("ov-policy-{mode:?}")).await;
    let public = seed_theme(&pool, "ov-policy-public", 0, None).await;
    let private = seed_theme(&pool, "ov-policy-private", 0, None).await;
    seed_member(&pool, agent, public, "ov policy public", true).await;
    seed_group_member(&pool, member, group, private, "ov policy private").await;
    // Resolve on the superuser pool, BEFORE any downgrade (see
    // viewer_fixture::downgraded_pool's warning).
    let viewer = Viewer::resolve(&pool, member).await.expect("resolve");

    // Stamped arm.
    let scoped = viewer_fixture::scoped_pool_with_mode(&pool, mode).await;
    let mut r = scoped.read_as(&viewer).await.expect("read_as");
    r.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade the stamped connection");
    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *r)
        .await
        .expect("epigraph_bypass()");
    assert!(!bypass, "CALIBRATION: the stamped session must not bypass");
    let stamped = ClaimThemeRepository::overview_page(&mut *r, &viewer, None, 200)
        .await
        .expect("the stamped read must serve");
    r.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    r.commit().await.expect("commit");

    // Unstamped arm: same function, same viewer, nothing stamped.
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade the unstamped connection");
    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_bypass()");
    assert!(
        !bypass,
        "CALIBRATION: the unstamped session must not bypass"
    );
    let unstamped = ClaimThemeRepository::overview_page(&mut *conn, &viewer, None, 200)
        .await
        .expect("the unstamped read must not error");
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    let mut want = vec![(public, 1), (private, 1)];
    overview_order(&mut want);
    assert_eq!(
        pairs(&stamped),
        want,
        "COHERENCE ({mode:?}): the stamped read counts the member's own private member"
    );
    assert_eq!(stamped.total, 2);
    assert_eq!(
        pairs(&unstamped),
        vec![(public, 1)],
        "THE DIFFERENTIAL ({mode:?}): unstamped, the policy hides the private member \
         the $V predicate admits"
    );
    assert_eq!(unstamped.total, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_page_policy_half_on_a_stamped_connection_in_session_mode(pool: PgPool) {
    overview_policy_half(pool, epigraph_db::SessionGucMode::Session).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_page_policy_half_on_a_stamped_connection_in_transaction_mode(pool: PgPool) {
    overview_policy_half(pool, epigraph_db::SessionGucMode::Transaction).await;
}
