//! `ClaimRepository::regenerate_superseded_edge_factors_conn` (supersede SPEC
//! §11 K3) mints factors over other writers' edges, so it runs only on a
//! privileged session: an application session is refused before any
//! statement and mints nothing, while the NOSUPERUSER maintenance login (the
//! connection the supersede cascade and its deferred replay hold) mints the
//! edge's one `(type, pair)` slot.
//!
//! Every other K3 test reaches this function on a superuser pool, which a
//! missing guard would not change.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, DbError};
use sqlx::PgPool;
use uuid::Uuid;

/// A claim-to-claim `corroborates` edge `n -> m` between current claims with
/// its trigger-minted factor removed (the state a cascade's UPDATE leaves).
async fn factorless_edge(pool: &PgPool, agent: Uuid) -> (Uuid, Uuid, Uuid) {
    let n = fixture::seed_public_claim(pool, agent, "k3 privilege: successor").await;
    let m = fixture::seed_public_claim(pool, agent, "k3 privilege: other end").await;
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'corroborates') RETURNING id",
    )
    .bind(n)
    .bind(m)
    .fetch_one(pool)
    .await
    .expect("insert edge");
    sqlx::query("DELETE FROM factors WHERE properties->>'source_edge_id' = $1")
        .bind(edge.to_string())
        .execute(pool)
        .await
        .expect("drop the trigger's factor");
    assert_eq!(factors_on(pool, edge).await, 0, "PREMISE: factorless");
    (n, m, edge)
}

async fn factors_on(pool: &PgPool, edge: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM factors WHERE properties->>'source_edge_id' = $1")
        .bind(edge.to_string())
        .fetch_one(pool)
        .await
        .expect("count factors")
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_application_session_is_refused_and_mints_nothing(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "k3-privilege-app").await;
    let (n, _, edge) = factorless_edge(&pool, agent).await;
    // Resolve on the superuser pool first (the fixture's ordering rule).
    let v = Viewer::resolve(&pool, agent).await.expect("resolve");
    let csv = |g: &[Uuid]| g.iter().map(Uuid::to_string).collect::<Vec<_>>().join(",");
    let (groups, writable) = (
        csv(v.group_bind().expect("scoped viewer")),
        csv(v.writable_groups()),
    );

    let result = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.group_ids', $1, false), \
                    set_config('epigraph.writable_group_ids', $2, false), \
                    set_config('epigraph.principal_id', $3, false)",
        )
        .bind(groups)
        .bind(writable)
        .bind(agent.to_string())
        .execute(&mut *conn)
        .await
        .expect("stamp the session");
        let r =
            ClaimRepository::regenerate_superseded_edge_factors_conn(&mut conn, n, &[edge]).await;
        (conn, r)
    })
    .await;
    match result {
        Err(DbError::InvalidData { reason }) => assert!(
            reason.contains("runs only on a privileged (maintenance) connection"),
            "refused, but not by the privileged-session check: {reason}"
        ),
        other => panic!("an application session must be refused before any statement: {other:?}"),
    }
    assert_eq!(factors_on(&pool, edge).await, 0, "nothing was minted");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_maintenance_login_mints_the_edges_one_slot(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "k3-privilege-maint").await;
    let (n, m, edge) = factorless_edge(&pool, agent).await;

    let slots = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r =
            ClaimRepository::regenerate_superseded_edge_factors_conn(&mut conn, n, &[edge]).await;
        (conn, r)
    })
    .await
    .expect("the maintenance login is privileged");
    let (lo, hi) = if n < m { (n, m) } else { (m, n) };
    assert_eq!(
        slots,
        vec![format!("evidential_support:{lo},{hi}")],
        "one slot, over the edge's ordered pair"
    );
    assert_eq!(factors_on(&pool, edge).await, 1, "the factor exists");
}
