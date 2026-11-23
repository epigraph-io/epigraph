//! Backlogs 63bb3d2e and 1777638e: `perspectives` holds viewpoints only.
//!
//! Before migration 267 the edge factor and the DS evidence auto-wire wrote
//! one `perspectives` row per epistemic edge (`perspective_type = 'edge'`) and
//! per evidence row (`'evidence'`) so a mass function could be keyed to it by
//! foreign key, and every listing had to filter them out (e305a895). 267 moved
//! those keys onto `mass_functions.slot_kind` / `slot_id`, deleted the rows
//! and added `perspectives_not_bba_slot`, so no such row can exist and the
//! listings filter nothing.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{PerspectiveRepository, PgPool};
use uuid::Uuid;

/// The SQLSTATE of a refused write, if it was one.
fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

/// No path can write a slot-shaped perspective: a direct INSERT typed `edge`
/// or `evidence` is refused by `perspectives_not_bba_slot` (23514), and so is
/// the repository's `create` with either type. Every other type, and none,
/// is accepted. On the code before 267 both INSERTs succeed.
#[sqlx::test(migrations = "../../migrations")]
async fn no_perspective_row_can_be_typed_edge_or_evidence(pool: PgPool) {
    for kind in ["edge", "evidence"] {
        let err = sqlx::query(
            "INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, 'slot', $2)",
        )
        .bind(Uuid::new_v4())
        .bind(kind)
        .execute(&pool)
        .await
        .expect_err("a slot-typed perspective is refused");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some("23514"),
            "type {kind}: a CHECK violation ({err})"
        );
        assert!(
            err.to_string().contains("perspectives_not_bba_slot"),
            "type {kind}: refused by perspectives_not_bba_slot ({err})"
        );

        let created = PerspectiveRepository::create(
            &pool,
            "slot-typed through create",
            None,
            None,
            Some(kind),
            &[],
            None,
            None,
        )
        .await;
        assert!(
            created
                .as_ref()
                .is_err_and(|e| e.to_string().contains("perspectives_not_bba_slot")),
            "type {kind}: create is refused by the same CHECK ({created:?})"
        );
    }

    // Control: a genuine type and no type both land.
    for kind in [Some("analytical"), None] {
        sqlx::query("INSERT INTO perspectives (name, perspective_type) VALUES ('genuine', $1)")
            .bind(kind)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("type {kind:?} is accepted: {e}"));
    }
}

/// The listings return every visible perspective, a NULL-typed one included
/// (the filter e305a895 added had to be NULL-safe; with no slot rows left
/// there is nothing to filter).
#[sqlx::test(migrations = "../../migrations")]
async fn list_and_list_by_agent_return_every_genuine_perspective(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "list-owner").await;
    let typed = PerspectiveRepository::create(
        &pool,
        "list-genuine-analytical",
        None,
        Some(agent),
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("create a genuine perspective");
    let untyped: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ('list-genuine-untyped', $1) \
         RETURNING id",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("insert an untyped perspective");

    let viewer = fixture::public_viewer(&pool).await;
    let listed: Vec<Uuid> = PerspectiveRepository::list(&pool, &viewer, 100, 0)
        .await
        .expect("list")
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert!(
        listed.contains(&typed.id),
        "a typed perspective is listed: {listed:?}"
    );
    assert!(
        listed.contains(&untyped),
        "an untyped perspective is listed: {listed:?}"
    );

    let mut by_agent: Vec<Uuid> =
        PerspectiveRepository::list_by_agent(&pool, &viewer, agent, 100, 0)
            .await
            .expect("list_by_agent")
            .into_iter()
            .map(|r| r.id)
            .collect();
    by_agent.sort();
    let mut expected = vec![typed.id, untyped];
    expected.sort();
    assert_eq!(
        by_agent, expected,
        "the agent's two perspectives, and only them"
    );
}
