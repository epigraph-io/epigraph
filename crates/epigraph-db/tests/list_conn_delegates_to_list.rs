//! `ClaimRepository::list_conn` and `::list` are ONE predicate.
//!
//! # What this replaces
//!
//! `list_conn` was a full hand-written copy of `list`: same seven projected
//! columns, same two query shapes, same `/* {VISIBILITY:claims} */` marker, same
//! bind indices. Identical at the time it was written, and kept identical by
//! nothing — `visibility_lint.rs` checks that each SQL text carries a marker,
//! never that two texts agree, so a fix applied to one and not the other is
//! invisible to every gate in this workspace. That is the class that produced
//! `get_by_id_conn`'s projection drift.
//!
//! `list_conn` now delegates: `Self::list(&mut *conn, viewer, ..)`. `&mut
//! PgConnection` implements `PgExecutor`, so it is the same statement on the
//! same connection, matching the shape `count_conn` was collapsed to first.
//!
//! # Why an equivalence assertion and not two separate ones
//!
//! Asserting "`list` suppresses" and "`list_conn` suppresses" in two arms is
//! what the duplicated bodies already had, and it passes just as happily when
//! the two predicates have drifted apart — each arm is still correct about its
//! own copy. The property that was missing is that they AGREE, so that is what
//! is asserted: one corpus, one viewer, both functions, identical output.
//!
//! Both query shapes are driven (`content_contains` present and absent), because
//! each shape is a separate SQL literal with its own bind index, and an
//! equivalence proved on one shape says nothing about the other.

use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

mod viewer_fixture;
use viewer_fixture as fixture;

async fn both(pool: &PgPool, viewer: &Viewer, search: Option<&str>) -> (Vec<Uuid>, Vec<Uuid>) {
    let via_executor = ClaimRepository::list(pool, viewer, 100, 0, search)
        .await
        .expect("list on the pool");

    let mut conn = pool.acquire().await.expect("acquire a connection");
    let via_conn = ClaimRepository::list_conn(&mut conn, viewer, 100, 0, search)
        .await
        .expect("list_conn on that connection");

    (
        via_executor.iter().map(|c| c.id.as_uuid()).collect(),
        via_conn.iter().map(|c| c.id.as_uuid()).collect(),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_conn_returns_exactly_what_list_returns_for_the_same_viewer(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "listconn-owner").await;
    let mine = fixture::seed_group_claim(&pool, owner, group, "listconn needle mine").await;
    let open = fixture::seed_public_claim(&pool, owner, "listconn needle public").await;

    let (stranger_agent, stranger_group) =
        fixture::seed_agent_with_group(&pool, "listconn-stranger").await;
    let theirs = fixture::seed_group_claim(
        &pool,
        stranger_agent,
        stranger_group,
        "listconn needle theirs",
    )
    .await;

    let owner_viewer = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger = fixture::public_viewer(&pool).await;

    for (who, viewer) in [("owner", &owner_viewer), ("stranger", &stranger)] {
        for shape in [None, Some("listconn needle")] {
            let (via_executor, via_conn) = both(&pool, viewer, shape).await;
            assert_eq!(
                via_executor, via_conn,
                "list and list_conn disagreed for the {who} viewer on the \
                 {shape:?} shape. One predicate in two texts is a silent leak \
                 the moment they diverge, which is why this asserts equality \
                 rather than asserting each side separately."
            );
        }
    }

    // The equality above is necessary and NOT sufficient, and this is the half
    // that matters. Now that both entry points run one body, a predicate
    // neutralised in that body leaks through BOTH and the two sides stay equal
    // — an equivalence assertion alone would be green. So the row sets are
    // pinned exactly, on BOTH shapes, through BOTH entry points.
    //
    // Measured while writing this: OR-ing away the no-search shape's predicate
    // in `list` left the equality arm green and was caught only here.
    for shape in [None, Some("listconn needle")] {
        let (owner_rows, owner_conn_rows) = both(&pool, &owner_viewer, shape).await;
        assert!(
            owner_rows.contains(&mine) && owner_rows.contains(&open),
            "CLASS P on the {shape:?} shape: the owner must see its own \
             group-private claim and the public one"
        );
        assert!(
            !owner_rows.contains(&theirs) && !owner_conn_rows.contains(&theirs),
            "neither entry point may return another group's claim on the \
             {shape:?} shape"
        );

        let (stranger_rows, stranger_conn_rows) = both(&pool, &stranger, shape).await;
        assert_eq!(
            stranger_rows,
            vec![open],
            "a stranger must see exactly the public claim through `list` on the \
             {shape:?} shape"
        );
        assert_eq!(
            stranger_conn_rows,
            vec![open],
            "…and exactly the same through `list_conn` on the {shape:?} shape"
        );
    }
}
