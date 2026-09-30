//! Migration 122: operator binding. Once a database is ARMED, a claim may be
//! authored only by a bound agent (a human operator, or the holder of a live
//! operator link); anything else is refused with SQLSTATE `OPL01`, on every
//! role, by a trigger no write path can skip.
//!
//! Most arms write through the superuser harness connection ON PURPOSE: the
//! trigger must hold for a role that bypasses every grant and every row-security
//! policy, because "a raw INSERT cannot bypass it" is the property. The
//! role-specific arms (the app role is refused the same way; only the
//! maintenance role arms; nobody but a superuser disarms) run under
//! `SET SESSION AUTHORIZATION` (`fixture::as_role`), which changes
//! `session_user` as well as `current_user`.
//!
//! # Verified to fail
//!
//! Each mutation of `migrations/122_operator_binding.sql` applied alone, then
//! restored (and the file touched so the next build re-embeds it):
//!
//! * the `CREATE TRIGGER` removed: fails
//!   `once_armed_an_unbound_author_is_refused_with_opl01_on_every_role` and
//!   `an_update_that_hands_a_claim_to_an_unbound_author_is_refused`;
//! * `epigraph_operator_binding_enforced` ignoring the arming row (always
//!   `true` unless the valve is off): fails
//!   `an_unarmed_database_admits_an_unbound_author`;
//! * `NOT l.retired` dropped from `epigraph_author_binding`: fails
//!   `a_live_link_and_a_human_operator_are_bound_and_a_retired_link_is_not`;
//! * the valve clause dropped from `epigraph_operator_binding_enforced`: fails
//!   `the_valve_lifts_enforcement_for_its_own_session_only`;
//! * `GRANT ... UPDATE, DELETE` on `operator_binding_arming` to the maintenance
//!   role: fails `arming_is_maintenance_only_audited_and_one_way`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::AgentRepository;
use sqlx::PgPool;
use uuid::Uuid;

const OPL01: &str = "OPL01";
const INSUFFICIENT_PRIVILEGE: &str = "42501";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

/// A `('public', group)` claim by `agent`, on whatever connection `exec` is.
async fn insert_claim<'e, E>(exec: E, agent: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = Uuid::new_v4();
    let hash = id.as_bytes().repeat(2);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("operator binding probe {id}"))
    .bind(hash)
    .bind(agent)
    .bind(group)
    .execute(exec)
    .await?;
    Ok(id)
}

/// Arm the database as the maintenance role would.
async fn arm(pool: &PgPool) -> bool {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let armed_now: bool =
            sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
                .fetch_one(&mut *conn)
                .await
                .expect("the maintenance role arms");
        (conn, armed_now)
    })
    .await
}

/// An ACTIVE human OAuth client whose graph agent is `agent`.
async fn make_human(pool: &PgPool, agent: Uuid) {
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, 'operator binding human', 'human', ARRAY['claims:write'], 'active', $2)",
    )
    .bind(format!("human-{agent}"))
    .bind(agent)
    .execute(pool)
    .await
    .expect("human client");
}

fn assert_opl01(r: Result<Uuid, sqlx::Error>, what: &str) {
    match r {
        Ok(id) => panic!("{what}: the claim {id} was written by an unbound author"),
        Err(e) => {
            assert_eq!(
                sqlstate(&e).as_deref(),
                Some(OPL01),
                "{what}: expected OPL01, got {e}"
            );
            let text = e.to_string();
            assert!(
                text.contains("not bound to a human operator"),
                "{what}: the refusal must say why: {text}"
            );
        }
    }
}

/// Applying 122 changes no write: an unbound author still writes on a database
/// nobody armed. This is what lets the deploy order migrate first and link
/// second, and what keeps every fixture in the workspace green.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unarmed_database_admits_an_unbound_author(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "unbound").await;
    let enforced: bool = sqlx::query_scalar("SELECT public.epigraph_operator_binding_enforced()")
        .fetch_one(&pool)
        .await
        .expect("enforced read");
    assert!(!enforced, "a freshly migrated database must not be armed");
    insert_claim(&pool, agent, group)
        .await
        .expect("an unarmed database admits an unbound author");
}

/// Armed: an unbound author is refused with OPL01 by the superuser harness
/// connection AND by the application role, and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn once_armed_an_unbound_author_is_refused_with_opl01_on_every_role(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "unbound").await;
    assert!(arm(&pool).await, "the first arm reports armed_now");

    assert_opl01(
        insert_claim(&pool, agent, group).await,
        "superuser raw INSERT",
    );

    let app = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = insert_claim(&mut *conn, agent, group).await;
        (conn, r)
    })
    .await;
    assert_opl01(app, "epigraph_app INSERT");

    let written: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(written, 0, "a refused author wrote {written} claim(s)");
}

/// Armed: (b) a LIVE link binds; (a) a human OAuth client's agent binds, and so
/// does an agent that operates others; a RETIRED link does not.
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_link_and_a_human_operator_are_bound_and_a_retired_link_is_not(pool: PgPool) {
    let (human, human_group) = fixture::seed_agent_with_group(&pool, "human").await;
    make_human(&pool, human).await;
    let (live, live_group) = fixture::seed_agent_with_group(&pool, "live").await;
    let (retired, retired_group) = fixture::seed_agent_with_group(&pool, "retired").await;
    let (operator_only, operator_only_group) =
        fixture::seed_agent_with_group(&pool, "operator-only").await;
    let (operated, _) = fixture::seed_agent_with_group(&pool, "operated").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, live, human)
            .await
            .expect("live link");
        AgentRepository::link_retired_agent(&mut conn, retired, human)
            .await
            .expect("retired link");
        // `operator_only` has no human client; it is a human operator only
        // because a link names it as the operator.
        AgentRepository::link_operator(&mut conn, operated, operator_only)
            .await
            .expect("link naming operator_only");
    }
    arm(&pool).await;

    let binding = |agent: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>("SELECT public.epigraph_author_binding($1)")
                .bind(agent)
                .fetch_one(&pool)
                .await
                .expect("binding read")
        }
    };
    assert_eq!(binding(human).await.as_deref(), Some("human_operator"));
    assert_eq!(
        binding(operator_only).await.as_deref(),
        Some("human_operator")
    );
    assert_eq!(binding(live).await.as_deref(), Some("live_link"));
    assert_eq!(binding(retired).await, None, "a retired link binds nothing");

    insert_claim(&pool, human, human_group)
        .await
        .expect("a human operator writes");
    insert_claim(&pool, operator_only, operator_only_group)
        .await
        .expect("an agent that operates others writes");
    insert_claim(&pool, live, live_group)
        .await
        .expect("a live-linked agent writes");
    assert_opl01(
        insert_claim(&pool, retired, retired_group).await,
        "a retired identity",
    );

    // A human whose client is no longer active, and whom no link names as an
    // operator, is not a human operator. (`human` above stays one through its
    // links even if its client is suspended: arm (a)'s second disjunct.)
    let (lapsed, lapsed_group) = fixture::seed_agent_with_group(&pool, "lapsed").await;
    make_human(&pool, lapsed).await;
    insert_claim(&pool, lapsed, lapsed_group)
        .await
        .expect("an active human client's agent writes");
    sqlx::query("UPDATE oauth_clients SET status = 'suspended' WHERE agent_id = $1")
        .bind(lapsed)
        .execute(&pool)
        .await
        .expect("suspend");
    assert_opl01(
        insert_claim(&pool, lapsed, lapsed_group).await,
        "a suspended human client's agent",
    );
}

/// The valve's transport: `epigraph.operator_link_enforcement = 'off'` lifts
/// enforcement for the session that set it, and for no other.
#[sqlx::test(migrations = "../../migrations")]
async fn the_valve_lifts_enforcement_for_its_own_session_only(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "unbound").await;
    arm(&pool).await;

    let mut valve = pool.acquire().await.expect("acquire");
    sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', 'off', false)")
        .execute(&mut *valve)
        .await
        .expect("set the valve");
    insert_claim(&mut *valve, agent, group)
        .await
        .expect("the valve admits an unbound author on its own session");

    let mut other = pool.acquire().await.expect("acquire");
    let on_other: String = sqlx::query_scalar(
        "SELECT COALESCE(current_setting('epigraph.operator_link_enforcement', true), '')",
    )
    .fetch_one(&mut *other)
    .await
    .expect("read setting");
    assert_ne!(on_other, "off", "the harness handed back the valve session");
    assert_opl01(
        insert_claim(&mut *other, agent, group).await,
        "a session without the valve",
    );

    sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', 'on', false)")
        .execute(&mut *valve)
        .await
        .expect("any other value");
    assert_opl01(
        insert_claim(&mut *valve, agent, group).await,
        "a valve set to anything but 'off'",
    );
}

/// The refusal reaches Rust as its NAMED form, which every write surface maps
/// to a denial, and its rendering names the code and the fix.
#[sqlx::test(migrations = "../../migrations")]
async fn opl01_maps_to_the_named_denial(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "unbound").await;
    arm(&pool).await;
    let e = insert_claim(&pool, agent, group)
        .await
        .expect_err("armed and unbound");
    let db = epigraph_db::DbError::from(e);
    assert!(
        matches!(db, epigraph_db::DbError::OperatorLinkRequired { .. }),
        "OPL01 must map to OperatorLinkRequired, got {db:?}"
    );
    assert!(db.is_write_authority_refusal());
    assert!(
        !db.is_personal_group_refusal(),
        "OPL01 is not a personal-group refusal"
    );
    let text = db.to_string();
    assert!(
        text.contains("OPL01") && text.contains("epigraph-operator link"),
        "{text}"
    );
}

/// The default-declaration path refuses an unbound author BEFORE it resolves a
/// personal group, so no group is provisioned for an agent that may not write;
/// a bound author (and every author on an unarmed database) resolves as before.
#[sqlx::test(migrations = "../../migrations")]
async fn default_decl_refuses_an_unbound_author_before_provisioning_a_group(pool: PgPool) {
    let bare = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(bare)
        .bind(bare.as_bytes().repeat(2))
        .execute(&pool)
        .await
        .expect("bare agent");
    let groups_of = |agent: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
            )
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("group count")
        }
    };
    arm(&pool).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let refused = epigraph_db::ClaimRepository::default_decl_for_author(&mut conn, bare).await;
    assert!(
        matches!(
            refused,
            Err(epigraph_db::DbError::OperatorLinkRequired { .. })
        ),
        "an unbound author must be refused by name, got {refused:?}"
    );
    assert_eq!(
        groups_of(bare).await,
        0,
        "no personal group may be provisioned for a refused author"
    );

    // Bound as a human operator: resolves (and provisions) as before.
    make_human(&pool, bare).await;
    epigraph_db::ClaimRepository::default_decl_for_author(&mut conn, bare)
        .await
        .expect("a human operator resolves its personal group");
    assert_eq!(groups_of(bare).await, 1);
}

/// With the valve variable unset (this process never sets it), a connection
/// from a `ScopedPool` carries no valve and stays enforced. The valve-open half
/// is `operator_binding_valve.rs`, alone in its own process.
#[sqlx::test(migrations = "../../migrations")]
async fn a_scoped_pool_without_the_valve_stays_enforced(pool: PgPool) {
    assert!(
        std::env::var(epigraph_db::operator_binding::ENFORCEMENT_ENV).is_err(),
        "this test process must not carry the valve variable"
    );
    let (agent, group) = fixture::seed_agent_with_group(&pool, "unbound").await;
    arm(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    assert_opl01(
        insert_claim(scoped.inner(), agent, group).await,
        "a ScopedPool connection with the valve closed",
    );
}

/// Moving a claim to an unbound author is a claim write like any other.
#[sqlx::test(migrations = "../../migrations")]
async fn an_update_that_hands_a_claim_to_an_unbound_author_is_refused(pool: PgPool) {
    let (human, group) = fixture::seed_agent_with_group(&pool, "human").await;
    make_human(&pool, human).await;
    let (unbound, _) = fixture::seed_agent_with_group(&pool, "unbound").await;
    arm(&pool).await;
    let claim = insert_claim(&pool, human, group)
        .await
        .expect("the human writes");

    let r = sqlx::query("UPDATE claims SET agent_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(unbound)
        .execute(&pool)
        .await;
    let e = r.expect_err("a claim was handed to an unbound author");
    assert_eq!(sqlstate(&e).as_deref(), Some(OPL01), "{e}");

    // An UPDATE that does not change the author is untouched by the rule.
    sqlx::query("UPDATE claims SET truth_value = 0.6 WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("an unrelated update");
}

/// Arming is a maintenance act, audited once, and one-way: the app role can
/// neither call the arming definer nor write the table, and the maintenance
/// role can arm but can neither update nor delete the record.
#[sqlx::test(migrations = "../../migrations")]
async fn arming_is_maintenance_only_audited_and_one_way(pool: PgPool) {
    let app_arm = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = sqlx::query("SELECT * FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await;
        let w = sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
            .execute(&mut *conn)
            .await;
        (
            conn,
            (
                r.err().and_then(|e| sqlstate(&e)),
                w.err().and_then(|e| sqlstate(&e)),
            ),
        )
    })
    .await;
    assert_eq!(
        app_arm,
        (
            Some(INSUFFICIENT_PRIVILEGE.to_string()),
            Some(INSUFFICIENT_PRIVILEGE.to_string())
        ),
        "the application role must not be able to arm"
    );

    assert!(arm(&pool).await, "the first arm arms");
    assert!(!arm(&pool).await, "a second arm is a no-op");
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'operator.binding_armed'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit count");
    assert_eq!(audits, 1, "arming is audited exactly once");

    let disarm = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let d = sqlx::query("DELETE FROM operator_binding_arming")
            .execute(&mut *conn)
            .await;
        let u = sqlx::query("UPDATE operator_binding_arming SET armed_by = 'someone else'")
            .execute(&mut *conn)
            .await;
        (
            conn,
            (
                d.err().and_then(|e| sqlstate(&e)),
                u.err().and_then(|e| sqlstate(&e)),
            ),
        )
    })
    .await;
    assert_eq!(
        disarm,
        (
            Some(INSUFFICIENT_PRIVILEGE.to_string()),
            Some(INSUFFICIENT_PRIVILEGE.to_string())
        ),
        "the maintenance role must not be able to disarm or rewrite the record"
    );
    let still: bool = sqlx::query_scalar("SELECT public.epigraph_operator_binding_enforced()")
        .fetch_one(&pool)
        .await
        .expect("enforced read");
    assert!(still, "the database must still be armed");
}
