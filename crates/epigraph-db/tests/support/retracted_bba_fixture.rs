//! A RETRACTED mass function, made the only way production makes one: through
//! migration 184's `epigraph_retract_mass_function`, on the application role
//! (`epigraph_app`), stamped for a writer of the row's owning group (the
//! definer's owner arm). Never a direct `UPDATE … SET retracted_at`: the
//! retract guard refuses that on every session but a privileged one, and a
//! fixture that wrote the columns itself would prove nothing about rows the
//! definer writes.
//!
//! Shared by the K4a tests of several crates (SPEC §11 phase 1, K4a: every
//! delete or move of `mass_functions` keeps a retracted row). Each includes it
//! with `#[path = "…/epigraph-db/tests/support/retracted_bba_fixture.rs"]`.

#![allow(dead_code)]

use epigraph_db::repos::mass_function::{BbaRetractStatus, MassFunctionRepository};
use epigraph_db::visibility::Viewer;
use sqlx::{Executor, PgPool};
use uuid::Uuid;

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Retract `id` through the definer, as a writer of its owning group, and
/// return that writer. Panics (a fixture failure, not a test result) when the
/// row has no owning group, no live writer of it can be resolved, or the
/// definer does not answer `retracted`.
pub async fn retract_through_definer(pool: &PgPool, id: Uuid) -> Uuid {
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_group_id FROM mass_functions WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap_or_else(|e| panic!("fixture: read mass function {id}: {e}"));
    let owner = owner.unwrap_or_else(|| {
        panic!("fixture: mass function {id} has no owning group, so no owner can retract it")
    });
    let candidates: Vec<Uuid> = sqlx::query_scalar(
        "SELECT agent_id FROM group_memberships \
          WHERE group_id = $1 AND role IN ('admin', 'writer') ORDER BY agent_id",
    )
    .bind(owner)
    .fetch_all(pool)
    .await
    .expect("fixture: the owning group's writers");
    let mut writer: Option<(Uuid, Viewer)> = None;
    for agent in candidates {
        let v = Viewer::resolve(pool, agent)
            .await
            .expect("fixture: resolve a writer");
        if v.writable_groups().contains(&owner) {
            writer = Some((agent, v));
            break;
        }
    }
    let (agent, viewer) = writer.unwrap_or_else(|| {
        panic!("fixture: no live writer of group {owner} to retract mass function {id}")
    });

    let mut conn = pool.acquire().await.expect("fixture: acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("fixture: SET SESSION AUTHORIZATION epigraph_app");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(csv(viewer.group_bind().expect("fixture: a scoped viewer")))
    .bind(csv(viewer.writable_groups()))
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("fixture: stamp the writer");
    let out = MassFunctionRepository::retract_conn(
        &mut conn,
        id,
        "K4a fixture: retracted before the act under test",
        None,
    )
    .await;
    // Reset whatever happened, so the connection goes back to the pool as the
    // harness role.
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', '', false), \
                set_config('epigraph.writable_group_ids', '', false), \
                set_config('epigraph.principal_id', '', false)",
    )
    .execute(&mut *conn)
    .await
    .expect("fixture: clear the stamp");
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("fixture: RESET SESSION AUTHORIZATION");
    let out = out.unwrap_or_else(|e| panic!("fixture: the definer refused {id}: {e:?}"));
    assert_eq!(
        out.status,
        BbaRetractStatus::Retracted,
        "fixture: the definer must retract {id}"
    );
    let retracted: bool =
        sqlx::query_scalar("SELECT retracted_at IS NOT NULL FROM mass_functions WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("fixture: re-read the row");
    assert!(
        retracted,
        "fixture: {id} carries retracted_at after the definer"
    );
    agent
}

/// `(claim_id, retracted)` of a row, or `None` when it no longer exists. Read
/// on the harness connection.
pub async fn row_state(pool: &PgPool, id: Uuid) -> Option<(Uuid, bool)> {
    sqlx::query_as("SELECT claim_id, retracted_at IS NOT NULL FROM mass_functions WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or_else(|e| panic!("read mass function {id}: {e}"))
}
