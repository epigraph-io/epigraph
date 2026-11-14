//! Backlog 63bb3d2e: `PerspectiveRepository::list` lists viewpoints, not the
//! internal BBA-keying rows.
//!
//! `ensure_edge_perspective` and `ensure_evidence_perspective` write one
//! `perspectives` row per epistemic edge (`perspective_type = 'edge'`) and per
//! evidence row (`perspective_type = 'evidence'`) so a mass function can be
//! keyed to it by foreign key. Those rows are not viewpoints an agent chose,
//! and before this fix they were listed by `list_perspectives` and
//! `GET /api/v1/perspectives`, where they outnumber the real ones.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{PerspectiveRepository, PgPool};
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn list_omits_edge_and_evidence_slots_and_keeps_every_genuine_perspective(pool: PgPool) {
    let genuine = PerspectiveRepository::create(
        &pool,
        "list-genuine-analytical",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("create a genuine perspective");

    // A genuine perspective with NO type: the column is nullable, and a
    // filter written as a bare `perspective_type NOT IN (...)` evaluates to
    // NULL on this row and drops it.
    let untyped: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name) VALUES ('list-genuine-untyped') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("insert an untyped perspective");

    let edge_slot = Uuid::new_v4();
    let evidence_slot = Uuid::new_v4();
    PerspectiveRepository::ensure_edge_perspective(&pool, edge_slot, None)
        .await
        .expect("edge slot");
    PerspectiveRepository::ensure_evidence_perspective(&pool, evidence_slot, None)
        .await
        .expect("evidence slot");

    let viewer = fixture::public_viewer(&pool).await;

    // CALIBRATION: every row above is visible to this viewer, so an internal
    // row's absence below is the type filter's doing and not visibility's.
    let visible_to_public: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM perspectives \
          WHERE id = ANY($1) AND visibility = 'public'",
    )
    .bind(vec![genuine.id, untyped, edge_slot, evidence_slot])
    .fetch_one(&pool)
    .await
    .expect("calibrate visibility");
    assert_eq!(
        visible_to_public, 4,
        "fixture: all four rows are public, so the viewer can see each of them"
    );

    let listed: Vec<Uuid> = PerspectiveRepository::list(&pool, &viewer, 100, 0)
        .await
        .expect("list")
        .into_iter()
        .map(|r| r.id)
        .collect();

    assert!(
        listed.contains(&genuine.id),
        "a typed genuine perspective is listed: {listed:?}"
    );
    assert!(
        listed.contains(&untyped),
        "a perspective with a NULL type is listed (the filter is NULL-safe): {listed:?}"
    );
    assert!(
        !listed.contains(&edge_slot),
        "an edge BBA slot (perspective_type = 'edge') is not listed: {listed:?}"
    );
    assert!(
        !listed.contains(&evidence_slot),
        "an evidence BBA slot (perspective_type = 'evidence') is not listed: {listed:?}"
    );

    // The slot rows are still readable by id: hiding them from the listing
    // must not break the get path the belief tools use.
    let by_id = PerspectiveRepository::get_by_id(&pool, &viewer, edge_slot)
        .await
        .expect("get_by_id");
    assert!(by_id.is_some(), "an edge slot is still readable by id");
}

/// The page is filled with genuine perspectives: internal slots are filtered
/// in SQL, before `LIMIT`, so a page is not short when slots are newest.
#[sqlx::test(migrations = "../../migrations")]
async fn a_page_is_not_shortened_by_internal_slots_newer_than_it(pool: PgPool) {
    let mut genuine = Vec::new();
    for i in 0..3 {
        let row = PerspectiveRepository::create(
            &pool,
            &format!("page-genuine-{i}"),
            None,
            None,
            Some("analytical"),
            &[],
            None,
            None,
        )
        .await
        .expect("create a genuine perspective");
        genuine.push(row.id);
    }
    // Five newer slots: ORDER BY created_at DESC puts them first.
    for _ in 0..5 {
        PerspectiveRepository::ensure_edge_perspective(&pool, Uuid::new_v4(), None)
            .await
            .expect("edge slot");
    }

    let viewer = fixture::public_viewer(&pool).await;
    let page: Vec<Uuid> = PerspectiveRepository::list(&pool, &viewer, 3, 0)
        .await
        .expect("list")
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(page.len(), 3, "a limit-3 page holds three rows: {page:?}");
    for id in &genuine {
        assert!(page.contains(id), "page holds every genuine row: {page:?}");
    }
}

/// `GET /api/v1/agents/:id/perspectives` reads `list_by_agent`, and both
/// slot writers stamp the writing agent as the owner, so an agent's own
/// listing is the second surface of the same leak.
#[sqlx::test(migrations = "../../migrations")]
async fn list_by_agent_omits_the_agents_own_edge_and_evidence_slots(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "slot-owner").await;
    let genuine = PerspectiveRepository::create(
        &pool,
        "agent-genuine",
        None,
        Some(agent),
        Some("narrative"),
        &[],
        None,
        None,
    )
    .await
    .expect("create a genuine perspective");
    let edge_slot = Uuid::new_v4();
    let evidence_slot = Uuid::new_v4();
    PerspectiveRepository::ensure_edge_perspective(&pool, edge_slot, Some(agent))
        .await
        .expect("edge slot");
    PerspectiveRepository::ensure_evidence_perspective(&pool, evidence_slot, Some(agent))
        .await
        .expect("evidence slot");

    // CALIBRATION: the agent owns all three rows and the viewer sees them all.
    let owned_public: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM perspectives \
          WHERE owner_agent_id = $1 AND visibility = 'public'",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("calibrate");
    assert_eq!(
        owned_public, 3,
        "fixture: three public rows owned by the agent"
    );

    let viewer = fixture::public_viewer(&pool).await;
    let listed: Vec<Uuid> = PerspectiveRepository::list_by_agent(&pool, &viewer, agent, 100, 0)
        .await
        .expect("list_by_agent")
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(
        listed,
        vec![genuine.id],
        "only the agent's genuine perspective is listed"
    );
}
