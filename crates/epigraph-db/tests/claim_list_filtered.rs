//! `ClaimRepository::list_filtered` / `count_filtered`: every filter of
//! `GET /api/v1/claims` is evaluated in SQL, and the two agree.
//!
//! Before these existed the handler fetched `list(10_000, 0)`, the newest
//! 10,000 rows, and filtered, sorted and counted them in memory (backlog
//! `2265a67b`). The route-level proof that the window is gone lives in
//! `epigraph-api/tests/claims_query_filters_past_the_window.rs`. This file pins
//! what the SQL itself does:
//!
//! * each filter narrows to exactly the expected rows, and `count_filtered`
//!   over the same filter reports that many;
//! * the statement's bind numbering holds with EVERY filter set, for both a
//!   `Scoped` viewer (which binds a group array last) and a `Bypass` viewer
//!   (which renders no placeholder and binds nothing). An off-by-one here is a
//!   runtime arity error that no type check catches;
//! * `search` is a literal substring: `%` and `_` do not act as wildcards;
//! * the `id` tiebreak makes paging over tied sort keys complete and
//!   non-overlapping;
//! * a trace or evidence row the viewer cannot read does not satisfy the
//!   methodology / evidence-type filter. Without the markers inside the two
//!   EXISTS subqueries, the listing would reveal that the hidden row exists.
//!
//! `#[sqlx::test]` gives each test a fresh database that no migration puts a
//! claim into, so every expected set below is exact.

mod viewer_fixture;
use viewer_fixture as fixture;

use chrono::{DateTime, Duration, Utc};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimListFilter, ClaimListSort, ClaimRepository, SortDirection};
use sqlx::PgPool;
use uuid::Uuid;

/// Insert a public claim with explicit sort/filter columns.
async fn seed(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    truth: f64,
    is_current: bool,
    created_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    let world = fixture::world_group(pool).await;
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'public', $7, $8, $8)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(truth)
    .bind(agent)
    .bind(is_current)
    .bind(world)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// The page (in order) and the count for one filter.
async fn run(
    pool: &PgPool,
    viewer: &Viewer,
    filter: &ClaimListFilter<'_>,
    sort: ClaimListSort,
    direction: SortDirection,
) -> (Vec<Uuid>, i64) {
    let rows = ClaimRepository::list_filtered(pool, viewer, filter, sort, direction, 100, 0)
        .await
        .expect("list_filtered");
    let count = ClaimRepository::count_filtered(pool, viewer, filter)
        .await
        .expect("count_filtered");
    (rows.iter().map(|c| c.id.as_uuid()).collect(), count)
}

/// Default order, sorted into a set for the comparisons that are about
/// membership only.
async fn members(pool: &PgPool, viewer: &Viewer, filter: ClaimListFilter<'_>) -> Vec<Uuid> {
    let (mut got, count) = run(
        pool,
        viewer,
        &filter,
        ClaimListSort::CreatedAt,
        SortDirection::Desc,
    )
    .await;
    assert_eq!(
        count as usize,
        got.len(),
        "count_filtered must agree with list_filtered for {filter:?}"
    );
    got.sort();
    got
}

fn set(ids: &[Uuid]) -> Vec<Uuid> {
    let mut v = ids.to_vec();
    v.sort();
    v
}

struct Corpus {
    agent_a: Uuid,
    now: DateTime<Utc>,
    a_old: Uuid,
    a_new: Uuid,
    b_mid: Uuid,
    b_new: Uuid,
}

/// Four public claims that differ on every filtered column.
///
/// | claim | agent | truth | current | age | content | trace | evidence |
/// |---|---|---|---|---|---|---|---|
/// | a_old | A | 0.9 | yes | 30d | `alpha 50% off` | deductive | document |
/// | a_new | A | 0.2 | yes | 1d | `alpha 500 items` | inductive | - |
/// | b_mid | B | 0.6 | no | 10d | `beta a_b` | - | observation |
/// | b_new | B | 0.4 | yes | 0d | `beta axb` | - | - |
async fn corpus(pool: &PgPool) -> Corpus {
    let (agent_a, _) = fixture::seed_agent_with_group(pool, "clf-a").await;
    let (agent_b, _) = fixture::seed_agent_with_group(pool, "clf-b").await;
    let now = Utc::now();

    let a_old = seed(
        pool,
        agent_a,
        "alpha 50% off",
        0.9,
        true,
        now - Duration::days(30),
    )
    .await;
    fixture::seed_reasoning_trace(pool, a_old, "deductive").await;
    fixture::seed_evidence(pool, a_old, "document").await;

    let a_new = seed(
        pool,
        agent_a,
        "alpha 500 items",
        0.2,
        true,
        now - Duration::days(1),
    )
    .await;
    fixture::seed_reasoning_trace(pool, a_new, "inductive").await;

    let b_mid = seed(
        pool,
        agent_b,
        "beta a_b",
        0.6,
        false,
        now - Duration::days(10),
    )
    .await;
    fixture::seed_evidence(pool, b_mid, "observation").await;

    let b_new = seed(pool, agent_b, "beta axb", 0.4, true, now).await;

    Corpus {
        agent_a,
        now,
        a_old,
        a_new,
        b_mid,
        b_new,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_filter_narrows_in_sql_and_the_count_agrees(pool: PgPool) {
    let c = corpus(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let v = &viewer;
    let p = &pool;

    // CALIBRATION: no filter returns all four, newest first. Every narrower
    // result below is therefore the filter's doing.
    let (all, total) = run(
        p,
        v,
        &ClaimListFilter::default(),
        ClaimListSort::CreatedAt,
        SortDirection::Desc,
    )
    .await;
    assert_eq!(all, vec![c.b_new, c.a_new, c.b_mid, c.a_old]);
    assert_eq!(total, 4);

    let f = ClaimListFilter::default;
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                truth_min: Some(0.5),
                ..f()
            }
        )
        .await,
        set(&[c.a_old, c.b_mid])
    );
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                truth_max: Some(0.4),
                ..f()
            }
        )
        .await,
        set(&[c.a_new, c.b_new])
    );
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                agent_id: Some(c.agent_a),
                ..f()
            }
        )
        .await,
        set(&[c.a_old, c.a_new])
    );
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                exclude_agent_id: Some(c.agent_a),
                ..f()
            }
        )
        .await,
        set(&[c.b_mid, c.b_new])
    );
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                is_current: Some(false),
                ..f()
            }
        )
        .await,
        set(&[c.b_mid])
    );
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                is_current: Some(true),
                ..f()
            }
        )
        .await,
        set(&[c.a_old, c.a_new, c.b_new])
    );
    let cutoff = c.now - Duration::days(5);
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                created_after: Some(cutoff),
                ..f()
            }
        )
        .await,
        set(&[c.a_new, c.b_new])
    );
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                created_before: Some(cutoff),
                ..f()
            }
        )
        .await,
        set(&[c.a_old, c.b_mid])
    );
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                methodology: Some("deductive"),
                ..f()
            }
        )
        .await,
        set(&[c.a_old])
    );
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                evidence_type: Some("observation"),
                ..f()
            }
        )
        .await,
        set(&[c.b_mid])
    );
    assert_eq!(
        members(
            p,
            v,
            ClaimListFilter {
                search: Some("ALPHA"),
                ..f()
            }
        )
        .await,
        set(&[c.a_old, c.a_new]),
        "search is case-insensitive"
    );
}

/// `%` and `_` in the search text are literal characters.
///
/// Unescaped, `%50%%` matches `alpha 500 items` and `%a_b%` matches
/// `beta axb`. The old in-memory `contains()` treated them as literals, so
/// escaping keeps that behaviour now the whole filter runs in SQL.
#[sqlx::test(migrations = "../../migrations")]
async fn search_treats_like_metacharacters_as_literals(pool: PgPool) {
    let c = corpus(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let f = ClaimListFilter::default;

    assert_eq!(
        members(
            &pool,
            &viewer,
            ClaimListFilter {
                search: Some("50%"),
                ..f()
            }
        )
        .await,
        set(&[c.a_old]),
        "`50%` must not match `alpha 500 items`"
    );
    assert_eq!(
        members(
            &pool,
            &viewer,
            ClaimListFilter {
                search: Some("a_b"),
                ..f()
            }
        )
        .await,
        set(&[c.b_mid]),
        "`a_b` must not match `beta axb`"
    );
    // CALIBRATION: a plain substring still matches both, so the two narrowings
    // above come from escaping and not from a broken search.
    assert_eq!(
        members(
            &pool,
            &viewer,
            ClaimListFilter {
                search: Some("50"),
                ..f()
            }
        )
        .await,
        set(&[c.a_old, c.a_new])
    );
}

/// Every filter set at once, which gives the statement its maximum bind count
/// (ten filter values, `LIMIT`, `OFFSET`, then the group array), on both viewer
/// shapes. A `Scoped` viewer binds the group array at `$13`; a `Bypass` viewer
/// renders no placeholder and binds nothing, so `LIMIT`/`OFFSET` must not
/// depend on it.
#[sqlx::test(migrations = "../../migrations")]
async fn every_filter_at_once_binds_correctly_for_scoped_and_bypass_viewers(pool: PgPool) {
    let c = corpus(&pool).await;
    let everything = ClaimListFilter {
        search: Some("alpha"),
        truth_min: Some(0.5),
        truth_max: Some(1.0),
        agent_id: Some(c.agent_a),
        exclude_agent_id: Some(Uuid::new_v4()),
        is_current: Some(true),
        created_after: Some(c.now - Duration::days(60)),
        created_before: Some(c.now - Duration::days(5)),
        methodology: Some("deductive"),
        evidence_type: Some("document"),
    };

    let scoped = fixture::public_viewer(&pool).await;
    let (_scoped_pool, bypass) = fixture::bypass(&pool).await;
    assert!(
        scoped.group_bind().is_some() && bypass.group_bind().is_none(),
        "CALIBRATION: one viewer of each shape"
    );

    for (label, viewer) in [("scoped", &scoped), ("bypass", &bypass)] {
        for sort in [ClaimListSort::CreatedAt, ClaimListSort::TruthValue] {
            for direction in [SortDirection::Asc, SortDirection::Desc] {
                let (got, count) = run(&pool, viewer, &everything, sort, direction).await;
                assert_eq!(
                    (got, count),
                    (vec![c.a_old], 1),
                    "{label}/{sort:?}/{direction:?}: every filter together selects a_old only"
                );
            }
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn truth_value_sort_orders_the_whole_match_set(pool: PgPool) {
    let c = corpus(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;

    let (asc, _) = run(
        &pool,
        &viewer,
        &ClaimListFilter::default(),
        ClaimListSort::TruthValue,
        SortDirection::Asc,
    )
    .await;
    assert_eq!(asc, vec![c.a_new, c.b_new, c.b_mid, c.a_old]);

    let (desc, _) = run(
        &pool,
        &viewer,
        &ClaimListFilter::default(),
        ClaimListSort::TruthValue,
        SortDirection::Desc,
    )
    .await;
    assert_eq!(desc, vec![c.a_old, c.b_mid, c.b_new, c.a_new]);
}

/// Seven claims with the SAME `created_at` and `truth_value`. Without a
/// tiebreak Postgres may return ties in any order on each execution, so
/// consecutive pages can repeat one row and never return another.
#[sqlx::test(migrations = "../../migrations")]
async fn paging_over_tied_sort_keys_is_complete_and_disjoint(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "clf-ties").await;
    let viewer = fixture::public_viewer(&pool).await;
    let at = Utc::now() - Duration::days(2);

    let mut seeded = Vec::new();
    for i in 0..7 {
        seeded.push(seed(&pool, agent, &format!("tie {i}"), 0.5, true, at).await);
    }

    for sort in [ClaimListSort::CreatedAt, ClaimListSort::TruthValue] {
        for direction in [SortDirection::Asc, SortDirection::Desc] {
            let mut paged = Vec::new();
            for offset in [0_i64, 3, 6] {
                let page = ClaimRepository::list_filtered(
                    &pool,
                    &viewer,
                    &ClaimListFilter::default(),
                    sort,
                    direction,
                    3,
                    offset,
                )
                .await
                .expect("list_filtered page");
                paged.extend(page.iter().map(|c| c.id.as_uuid()));
            }
            let mut expected = seeded.clone();
            expected.sort();
            if direction == SortDirection::Desc {
                expected.reverse();
            }
            assert_eq!(
                paged, expected,
                "{sort:?}/{direction:?}: three pages over seven tied rows must return each \
                 row exactly once, in id order"
            );
        }
    }
}

/// A claim the viewer CAN read, whose only `deductive` trace and only
/// `document` evidence the viewer CANNOT read, must not match either filter.
///
/// The claim's presence in the response would otherwise tell a stranger that
/// the hidden row exists and what its type is.
///
/// # How the fixture gets a readable claim with an unreadable child
///
/// Migration 070's inheritance trigger copies the claim's tenancy onto a
/// trace or evidence row at INSERT, so both start public. Nothing re-applies
/// it on UPDATE, so the test narrows the two children to a private group
/// afterwards. That leaves the claim public and its trace and evidence private.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_trace_or_evidence_row_does_not_satisfy_the_filter(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "clf-oracle-owner").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "clf-oracle-stranger").await;

    let claim = seed(
        &pool,
        owner,
        "public claim with private children",
        0.7,
        true,
        Utc::now(),
    )
    .await;
    let trace = fixture::seed_reasoning_trace(&pool, claim, "deductive").await;
    let evidence = fixture::seed_evidence(&pool, claim, "document").await;
    sqlx::query(
        "UPDATE reasoning_traces SET visibility = 'group', owner_group_id = $2 WHERE id = $1",
    )
    .bind(trace)
    .bind(group)
    .execute(&pool)
    .await
    .expect("narrow the trace");
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(evidence)
        .bind(group)
        .execute(&pool)
        .await
        .expect("narrow the evidence");

    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");
    let f = ClaimListFilter::default;
    let by_method = ClaimListFilter {
        methodology: Some("deductive"),
        ..f()
    };
    let by_evidence = ClaimListFilter {
        evidence_type: Some("document"),
        ..f()
    };

    // CALIBRATION: the stranger CAN read the claim itself, so its absence below
    // is caused by the child predicate and not by the claim's own visibility.
    assert_eq!(members(&pool, &stranger_v, f()).await, vec![claim]);
    // CALIBRATION: the owner's group can read both children, so the filters
    // match when the viewer is entitled to the child rows.
    assert_eq!(members(&pool, &owner_v, by_method).await, vec![claim]);
    assert_eq!(members(&pool, &owner_v, by_evidence).await, vec![claim]);

    assert_eq!(
        members(&pool, &stranger_v, by_method).await,
        Vec::<Uuid>::new(),
        "a reasoning trace the stranger cannot read must not satisfy ?methodology="
    );
    assert_eq!(
        members(&pool, &stranger_v, by_evidence).await,
        Vec::<Uuid>::new(),
        "an evidence row the stranger cannot read must not satisfy ?evidence_type="
    );
}
