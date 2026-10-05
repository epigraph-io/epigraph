//! The operator-binding VALVE end to end (migration 122,
//! `epigraph_db::operator_binding`): with `EPIGRAPH_OPERATOR_LINK_ENFORCEMENT=off`
//! in the process environment, every connection a `ScopedPool` opens carries
//! the valve, and an armed database accepts an unbound author on it, while a
//! connection built without `ScopedPool` stays enforced.
//!
//! ONE test in this binary, on purpose: the variable is read once per process
//! (`enforcement()` is a `OnceLock`), so the test sets it before anything in
//! the process can read it, and no other test shares the process. The default
//! (valve closed) half is `operator_binding.rs::a_scoped_pool_without_the_valve_stays_enforced`.
//!
//! Verified to fail: `apply_valve` made a no-op (its `set_config` removed) ->
//! the scoped connection reads '' and the INSERT is refused with OPL01.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::operator_binding::{enforcement, Enforcement, ENFORCEMENT_ENV, VALVE_GUC};
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_claim<'e, E>(exec: E, agent: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("valve probe {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(agent)
    .bind(group)
    .execute(exec)
    .await?;
    Ok(id)
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_valve_env_reaches_every_scoped_connection_and_only_those(pool: PgPool) {
    std::env::set_var(ENFORCEMENT_ENV, "off");
    assert_eq!(
        enforcement(),
        Enforcement::Off,
        "the valve must read as off"
    );

    let (agent, group) = fixture::seed_agent_with_group(&pool, "unbound").await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;

    let url = fixture::database_url_for(&pool).await;
    let scoped = ScopedPool::connect(&url, SessionGucMode::Session)
        .await
        .expect("scoped pool");
    let mut conn = scoped.inner().acquire().await.expect("acquire");
    let setting: String = sqlx::query_scalar("SELECT COALESCE(current_setting($1, true), '')")
        .bind(VALVE_GUC)
        .fetch_one(&mut *conn)
        .await
        .expect("read valve");
    assert_eq!(
        setting, "off",
        "a ScopedPool connection must carry the valve"
    );
    insert_claim(&mut *conn, agent, group)
        .await
        .expect("the valve admits an unbound author on a scoped connection");

    // The harness pool was not built by ScopedPool: it stays enforced.
    let e = insert_claim(&pool, agent, group)
        .await
        .expect_err("a non-scoped connection must stay enforced");
    assert_eq!(
        e.as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("OPL01"),
        "{e}"
    );
}
