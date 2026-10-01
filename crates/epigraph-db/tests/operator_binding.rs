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
//!   role: fails `arming_is_maintenance_only_audited_and_one_way`;
//! * `epigraph_is_human_operator(l.operator_id)` dropped from arm (b): fails
//!   `a_live_link_and_a_human_operator_are_bound_and_a_retired_link_is_not`;
//! * the claims trigger's `epigraph_require_writer_scope` calls removed, and
//!   separately the `group_memberships_operator_scope` trigger removed: each
//!   fails `a_linked_agent_writes_only_where_its_own_operator_writes`.
//!
//! The tests added by the review fixes name their own mutations.

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

/// A registered HUMAN OPERATOR: an active human client AND a registry row.
async fn make_human(pool: &PgPool, agent: Uuid) {
    fixture::make_human_operator(pool, agent).await;
}

/// ONLY an active `human` OAuth client, with no registry row: the shape an
/// unauthenticated dynamic client registration produces.
async fn make_human_client_only(pool: &PgPool, agent: Uuid) {
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, 'dcr-shaped client', 'human', ARRAY['claims:write'], 'active', $2)",
    )
    .bind(format!("dcr-{agent}"))
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

/// Armed: (a) a human OAuth client's agent binds; (b) a LIVE link to a human
/// binds; a RETIRED link does not, and neither does a live link to an operator
/// that is not a human (a link cannot make a human), nor does being named as
/// some link's operator. (Superuser session: section 1b's group arm is exempt
/// here, so only the binding arm is measured.)
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
        // `operator_only` is no registered human: since 122 no link to it can
        // be recorded at all (section 1c), so `operated` stays unlinked.
        let refused = AgentRepository::link_operator(&mut conn, operated, operator_only).await;
        assert!(
            refused.is_err(),
            "a link to a non-registered operator must be refused: {refused:?}"
        );
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
    assert_eq!(binding(live).await.as_deref(), Some("live_link"));
    assert_eq!(binding(retired).await, None, "a retired link binds nothing");
    assert_eq!(
        binding(operator_only).await,
        None,
        "being named as an operator does not make an agent a human"
    );
    assert_eq!(
        binding(operated).await,
        None,
        "a live link to a non-human binds nobody to a human"
    );

    insert_claim(&pool, human, human_group)
        .await
        .expect("a human operator writes");
    insert_claim(&pool, live, human_group)
        .await
        .expect("a live-linked agent writes into its operator's group");
    let _ = live_group;
    assert_opl01(
        insert_claim(&pool, retired, retired_group).await,
        "a retired identity",
    );
    assert_opl01(
        insert_claim(&pool, operator_only, operator_only_group).await,
        "an operator that is not a human",
    );

    // A human whose client is no longer active is not a human operator.
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

/// Run `f` on a connection that is `epigraph_app`, stamped as `principal` with
/// `groups` as its read AND writable set, exactly the three GUCs `ScopedPool`
/// stamps; the stamp is cleared and the role reset afterwards.
async fn as_app_stamped<F, Fut, T>(pool: &PgPool, principal: Uuid, groups: &[Uuid], f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let set = groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $2, false)",
        )
        .bind(principal.to_string())
        .bind(&set)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let (mut conn, out) = f(conn).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(sqlstate)
}

/// Section 1b, with TWO humans (OB5): a live-linked agent writes only into
/// groups its OWN operator writes. Human B cannot enrol A's agent as a writer
/// in B's group, a membership that predates arming does not let the agent write
/// a claim there, and the agent's own personal group is not its operator's
/// either. Measured on the APPLICATION ROLE (a privileged session is exempt).
/// An instance-admin principal crosses groups.
///
/// Verified to fail: the `PERFORM ... epigraph_require_writer_scope` lines
/// removed from the claims trigger -> the write into B's group lands; the
/// membership trigger's `CREATE TRIGGER` removed -> B's enrolment lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_agent_writes_only_where_its_own_operator_writes(pool: PgPool) {
    let (a, a_group) = fixture::seed_agent_with_group(&pool, "human-a").await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "human-b").await;
    make_human(&pool, a).await;
    make_human(&pool, b).await;
    let (x, x_group) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "a-agent-y").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, x, a)
            .await
            .expect("x -> a");
        AgentRepository::link_operator(&mut conn, y, a)
            .await
            .expect("y -> a");
    }
    // Before arming, B enrolled X as a writer in B's group.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(b_group)
    .bind(x)
    .execute(&pool)
    .await
    .expect("unarmed: a membership B grants");
    arm(&pool).await;

    let (own, foreign, personal) = as_app_stamped(
        &pool,
        x,
        &[a_group, b_group, x_group],
        |mut conn| async move {
            let own = insert_claim(&mut *conn, x, a_group).await;
            let foreign = insert_claim(&mut *conn, x, b_group).await;
            let personal = insert_claim(&mut *conn, x, x_group).await;
            (conn, (own, foreign, personal))
        },
    )
    .await;
    assert!(own.is_ok(), "into its operator's group: {own:?}");
    assert_eq!(code_of(&foreign).as_deref(), Some("OPL02"), "{foreign:?}");
    let named = epigraph_db::DbError::from(foreign.expect_err("refused"));
    assert!(
        matches!(named, epigraph_db::DbError::OperatorScopeRefused { .. })
            && named.is_write_authority_refusal(),
        "OPL02 must map to OperatorScopeRefused: {named:?}"
    );
    assert_eq!(code_of(&personal).as_deref(), Some("OPL02"), "{personal:?}");

    // B, as itself, enrols A's other agent into B's group: refused at the door.
    let enrol = as_app_stamped(&pool, b, &[b_group], |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(b_group)
        .bind(y)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_eq!(
        code_of(&enrol).as_deref(),
        Some("OPL02"),
        "another human must not enrol my agent: {enrol:?}"
    );
    // A READER row is no write authority and stays allowed.
    as_app_stamped(&pool, b, &[b_group], |mut conn| async move {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'reader')",
        )
        .bind(b_group)
        .bind(y)
        .execute(&mut *conn)
        .await
        .expect("a reader row");
        (conn, ())
    })
    .await;

    // An instance-admin principal crosses groups.
    let (admin, _) = fixture::seed_agent_with_group(&pool, "instance-admin").await;
    make_human(&pool, admin).await;
    sqlx::query("INSERT INTO instance_admins (agent_id) VALUES ($1)")
        .bind(admin)
        .execute(&pool)
        .await
        .expect("instance admin");
    let crossed = as_app_stamped(&pool, admin, &[b_group], |mut conn| async move {
        let r = insert_claim(&mut *conn, x, b_group).await;
        (conn, r)
    })
    .await;
    assert!(crossed.is_ok(), "admin access crosses groups: {crossed:?}");
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

/// OB7: WHO IS A HUMAN is an explicit, audited, maintenance-only registry, and
/// neither half of the old test certifies alone.
///
/// * An agent with an active `human` client and NO registry row (the shape of
///   an unauthenticated dynamic client registration) cannot author (OPL01) and
///   cannot be linked to (refused at the link record, armed or not).
/// * The app role can neither write the registry nor call its definers.
/// * The maintenance role registers through the audited definer, which refuses
///   an agent with no active human client; the human then binds.
/// * Revoking the registration stops the human AND its live-linked agent
///   (OPL01), and an exact re-link of that existing link is still not refused
///   (a re-link records nothing new).
///
/// Verified to fail, each alone: the registry `EXISTS` removed from
/// `epigraph_is_human_operator` (the DCR-shaped author writes); the
/// `operator_links_operator_is_human` trigger removed (the link to it lands);
/// `GRANT INSERT` on `human_operators` to the app role (the app write lands);
/// the trigger's existing-row skip removed (the exact re-link is refused).
#[sqlx::test(migrations = "../../migrations")]
async fn the_human_registry_is_maintenance_written_audited_and_required(pool: PgPool) {
    let (dcr, dcr_group) = fixture::seed_agent_with_group(&pool, "dcr-shaped").await;
    make_human_client_only(&pool, dcr).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    arm(&pool).await;

    // A human client alone is not a human.
    assert_opl01(
        insert_claim(&pool, dcr, dcr_group).await,
        "a human client with no registry row",
    );
    {
        let mut conn = pool.acquire().await.expect("acquire");
        let r = AgentRepository::link_operator(&mut conn, agent, dcr).await;
        let text = format!("{r:?}");
        assert!(
            r.is_err() && text.contains("not a registered human operator"),
            "a link to a non-registered operator must be refused at the record: {text}"
        );
    }
    let links: i64 = sqlx::query_scalar("SELECT count(*) FROM operator_links WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("links");
    assert_eq!(links, 0);

    // The app role cannot write the registry, directly or through a definer.
    let (direct, definer) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let d = sqlx::query("INSERT INTO human_operators (agent_id, reason) VALUES ($1, 'x')")
            .bind(dcr)
            .execute(&mut *conn)
            .await;
        let f = sqlx::query("SELECT * FROM public.epigraph_register_human_operator($1, 'x')")
            .bind(dcr)
            .execute(&mut *conn)
            .await;
        (
            conn,
            (
                d.err().and_then(|e| sqlstate(&e)),
                f.err().and_then(|e| sqlstate(&e)),
            ),
        )
    })
    .await;
    assert_eq!(
        direct.as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "app INSERT"
    );
    assert_eq!(
        definer.as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "app register"
    );

    // The maintenance role registers through the audited definer.
    let (no_client, _) = fixture::seed_agent_with_group(&pool, "no-client").await;
    let (refused, registered) =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let refused = sqlx::query(
                "SELECT * FROM public.epigraph_register_human_operator($1, 'not a human')",
            )
            .bind(no_client)
            .execute(&mut *conn)
            .await
            .err()
            .and_then(|e| sqlstate(&e));
            let registered: bool = sqlx::query_scalar(
                "SELECT registered_now FROM public.epigraph_register_human_operator($1, 'test')",
            )
            .bind(dcr)
            .fetch_one(&mut *conn)
            .await
            .expect("maintenance registers");
            (conn, (refused, registered))
        })
        .await;
    assert_eq!(
        refused.as_deref(),
        Some("55000"),
        "an agent with no active human client"
    );
    assert!(registered);
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'operator.human_registered'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(audits, 1);
    insert_claim(&pool, dcr, dcr_group)
        .await
        .expect("a registered human writes");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, agent, dcr)
            .await
            .expect("a link to a registered human");
    }
    insert_claim(&pool, agent, dcr_group)
        .await
        .expect("its live-linked agent writes");

    // Revoked: the human and its agent stop; an exact re-link is not refused.
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'left')")
            .bind(dcr)
            .execute(&mut *conn)
            .await
            .expect("revoke");
        (conn, ())
    })
    .await;
    assert_opl01(insert_claim(&pool, dcr, dcr_group).await, "a revoked human");
    assert_opl01(
        insert_claim(&pool, agent, dcr_group).await,
        "the live-linked agent of a revoked human",
    );
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, dcr)
        .await
        .expect("an exact re-link of an existing link records nothing and is not refused");
}

/// Link `agent` live to `operator` (a registered human) on the harness pool.
async fn link_live(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("live link");
}

/// A `('public', group)` claim by `author` inserted on an `epigraph_app`
/// connection stamped as `writer` with `groups` readable AND writable.
async fn write_as(
    pool: &PgPool,
    writer: Uuid,
    groups: &[Uuid],
    author: Uuid,
    owner: Uuid,
) -> Result<Uuid, sqlx::Error> {
    as_app_stamped(pool, writer, groups, |mut conn| async move {
        let r = insert_claim(&mut *conn, author, owner).await;
        (conn, r)
    })
    .await
}

/// Review SEC-1 / SEC-2: the trigger binds the WRITER (the session principal
/// `ScopedPool` stamps from the authenticated viewer), not only the author
/// column the request supplies. Two humans; X is A's agent, Y is B's, U is
/// bound to nobody. Every write is on the application role, and the stamps
/// deliberately make the owner group writable, so row security (and the orphan
/// permissive policies a production database may still carry) admits the row
/// and the trigger alone decides.
///
/// Verified to fail: the trigger's writer branch replaced by the author-only
/// checks (the pre-review body) -> U's write naming human A lands, and Y's
/// write naming human A inside B's group lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_writer_is_bound_not_only_the_author_column(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, b_group) = fixture::seed_human_operator(&pool, "human-b").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "b-agent-y").await;
    let (u, u_group) = fixture::seed_agent_with_group(&pool, "unbound-u").await;
    link_live(&pool, x, a).await;
    link_live(&pool, y, b).await;
    arm(&pool).await;

    // An unbound writer, whatever author it names, writes nothing.
    for (author, owner, what) in [
        (a, u_group, "U names human A, owned by U's own group"),
        (a, a_group, "U names human A, owned by A's group"),
        (x, a_group, "U names A's agent X, owned by A's group"),
    ] {
        let r = write_as(&pool, u, &[u_group, a_group], author, owner).await;
        assert_opl01(r, what);
    }

    // A bound writer may name only an author of its own human.
    for (author, what) in [
        (a, "B's agent Y names human A in B's group"),
        (x, "B's agent Y names A's agent X in B's group"),
    ] {
        let r = write_as(&pool, y, &[b_group], author, b_group).await;
        assert_eq!(code_of(&r).as_deref(), Some("OPL02"), "{what}: {r:?}");
    }
    // Nor write, under its own name, where its human does not write.
    let r = write_as(&pool, y, &[a_group], y, a_group).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some("OPL02"),
        "Y into A's group: {r:?}"
    );

    // Controls: its own name in its human's group; a human naming its agent.
    write_as(&pool, y, &[b_group], y, b_group)
        .await
        .expect("Y as itself into B's group");
    write_as(&pool, a, &[a_group], x, a_group)
        .await
        .expect("human A names its own agent X in its own group");
    let wrong: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE agent_id = $1 AND owner_group_id <> $2",
    )
    .bind(a)
    .bind(a_group)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(wrong, 0, "no claim attributed to A outside A's group");
}

/// Review SEC-4: once armed, the real supersede act
/// (`ClaimRepository::supersede_act_conn`, which declares no owner and
/// inherits the old claim's author) works for a live-linked agent superseding
/// its own claim and for a human superseding its RETIRED legacy author's claim,
/// and is refused for an unbound writer. A fresh claim naming the retired
/// author is refused.
///
/// Verified to fail: the trigger renamed back to sort before
/// `claims_require_tenancy` -> X's supersede is refused OPL02 on a NULL owner;
/// `epigraph_require_attributable` reading only LIVE links for the author ->
/// A's supersede of the legacy claim is refused OPL01; the trigger passing
/// `true` for `p_inherited` whatever `supersedes` says -> the fresh claim
/// naming the retired author lands; the trigger passing
/// `NEW.supersedes IS NOT NULL` (not "an INSERT carrying the predecessor's
/// author") -> the posed supersede and the re-attributed successor land.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_is_bound_on_the_writer_once_armed(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "legacy").await;
    let (u, u_group) = fixture::seed_agent_with_group(&pool, "unbound-u").await;
    link_live(&pool, x, a).await;
    let x_claim = insert_claim(&pool, x, a_group).await.expect("X's claim");
    let legacy_claim = insert_claim(&pool, legacy, a_group)
        .await
        .expect("legacy claim");
    let a_claim = insert_claim(&pool, a, a_group).await.expect("A's claim");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_retired_agent(&mut conn, legacy, a)
            .await
            .expect("the legacy author's retired tie");
    }
    arm(&pool).await;

    let supersede = |writer: Uuid, groups: Vec<Uuid>, old: Uuid| {
        let pool = pool.clone();
        async move {
            as_app_stamped(&pool, writer, &groups, |mut conn| async move {
                let r = {
                    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
                    let r = epigraph_db::ClaimRepository::supersede_act_conn(
                        &mut tx,
                        epigraph_core::ClaimId::from_uuid(old),
                        &format!("revision of {old}"),
                        epigraph_core::TruthValue::new(0.6).expect("truth"),
                        "operator binding probe",
                    )
                    .await;
                    if r.is_ok() {
                        tx.commit().await.expect("commit");
                    }
                    r
                };
                (conn, r)
            })
            .await
        }
    };

    let (new_x, _) = supersede(x, vec![a_group], x_claim)
        .await
        .expect("a live-linked agent supersedes its own claim once armed");
    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(new_x)
        .fetch_one(&pool)
        .await
        .expect("owner");
    assert_eq!(owner, a_group, "the successor inherits the owner group");

    supersede(a, vec![a_group], legacy_claim)
        .await
        .expect("a human supersedes its own retired legacy author's claim once armed");

    // The retired author is admissible only as the author a supersede
    // INHERITS: a FRESH claim naming it is refused (OB1: the author is a human
    // or holds a live link), even by its own human.
    assert_opl01(
        write_as(&pool, a, &[a_group], legacy, a_group).await,
        "a fresh claim naming a retired identity",
    );

    // Delta review SEC-D4 / COR-D2 / DIS-D5: pointing `supersedes` at a claim
    // whose author is NOT the retired identity is not inheritance. A fresh
    // row naming the retired author with `supersedes` = X's own claim, and a
    // row inserted as X's supersede then re-attributed to the retired author,
    // are both refused; the predecessor stays current.
    let posed = as_app_stamped(&pool, x, &[a_group], |mut conn| async move {
        let id = Uuid::new_v4();
        let r = sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id, supersedes) \
             VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5, $6)",
        )
        .bind(id)
        .bind(format!("posing as a supersede {id}"))
        .bind(id.as_bytes().repeat(2))
        .bind(legacy)
        .bind(a_group)
        .bind(new_x)
        .execute(&mut *conn)
        .await
        .map(|_| id);
        (conn, r)
    })
    .await;
    assert_opl01(
        posed,
        "a fresh claim naming a retired identity, supersedes = another author's claim",
    );
    let reattributed = as_app_stamped(&pool, x, &[a_group], |mut conn| async move {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id, supersedes) \
             VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5, $6)",
        )
        .bind(id)
        .bind(format!("X's own successor {id}"))
        .bind(id.as_bytes().repeat(2))
        .bind(x)
        .bind(a_group)
        .bind(new_x)
        .execute(&mut *conn)
        .await
        .expect("X writes a successor naming itself");
        let r = sqlx::query("UPDATE claims SET agent_id = $2 WHERE id = $1")
            .bind(id)
            .bind(legacy)
            .execute(&mut *conn)
            .await
            .map(|_| id);
        (conn, r)
    })
    .await;
    assert!(
        reattributed.is_err(),
        "a successor re-attributed to a retired identity landed: {reattributed:?}"
    );
    let x_still: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(new_x)
        .fetch_one(&pool)
        .await
        .expect("current");
    assert!(x_still, "the posed supersedes retired nothing");

    let refused = supersede(u, vec![u_group, a_group], a_claim)
        .await
        .expect_err("an unbound writer must not supersede");
    assert!(
        matches!(refused, epigraph_db::DbError::OperatorLinkRequired { .. }),
        "{refused:?}"
    );
    let still: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(a_claim)
        .fetch_one(&pool)
        .await
        .expect("current");
    assert!(still, "a refused supersede retires nothing");
}

/// A claim naming `author`, pointing `supersedes` at `pred`, owned by `owner`,
/// inserted on an application connection stamped as `writer` with `groups`.
async fn pose_successor(
    pool: &PgPool,
    writer: Uuid,
    groups: &[Uuid],
    author: Uuid,
    owner: Uuid,
    pred: Uuid,
) -> Result<Uuid, sqlx::Error> {
    as_app_stamped(pool, writer, groups, |mut conn| async move {
        let id = Uuid::new_v4();
        let r = sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id, supersedes) \
             VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5, $6)",
        )
        .bind(id)
        .bind(format!("posed successor {id}"))
        .bind(id.as_bytes().repeat(2))
        .bind(author)
        .bind(owner)
        .bind(pred)
        .execute(&mut *conn)
        .await
        .map(|_| id);
        (conn, r)
    })
    .await
}

/// Delta review round 2 SEC-R2-2 / DIS-R2-5: the inherited-author admission is
/// what the supersede act writes and nothing a writer can pose. A live agent of
/// the retired identity's own human may not mint fresh claims under that
/// identity by pointing `supersedes` at a CURRENT claim of it, at a claim in a
/// different group (the platform corpus included), or at a predecessor that
/// already has a current successor; nor launder an admitted successor into a
/// plain fresh claim by clearing or re-pointing its `supersedes`. A predecessor
/// in a group the writer cannot write is refused the same way whoever
/// authored it (no oracle). The real supersede act, and the dedup/consolidate
/// shape (re-point while retiring), still work.
///
/// Verified to fail, each alone: the inherited rule's `NOT COALESCE(p.is_current,
/// true)` dropped -> the successor of a current claim lands; its owner-group
/// equality dropped -> the successor of the retired world-owned claim lands in
/// A's group; its `NOT EXISTS` current-successor clause dropped -> the second
/// successor lands; the trigger's lineage branch reduced to `RETURN NEW` -> the
/// cleared and re-pointed lineage lands.
#[sqlx::test(migrations = "../../migrations")]
async fn an_inherited_author_is_one_retired_predecessor_restated_in_its_group(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, b_group) = fixture::seed_human_operator(&pool, "human-b").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "a-legacy").await;
    link_live(&pool, x, a).await;
    let world = Uuid::nil();
    let l1 = insert_claim(&pool, legacy, a_group).await.expect("l1");
    let l2 = insert_claim(&pool, legacy, a_group).await.expect("l2");
    let l_world = insert_claim(&pool, legacy, world)
        .await
        .expect("world, current");
    let l_world_retired = insert_claim(&pool, legacy, world).await.expect("world");
    let l_in_b = insert_claim(&pool, legacy, b_group)
        .await
        .expect("L in B's group");
    let b_in_b = insert_claim(&pool, b, b_group)
        .await
        .expect("B's own claim");
    let x_claim = insert_claim(&pool, x, a_group).await.expect("X's claim");
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(l_world_retired)
        .execute(&pool)
        .await
        .expect("retire the world claim");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_retired_agent(&mut conn, legacy, a)
            .await
            .expect("the legacy identity's retired tie to A");
    }
    arm(&pool).await;
    let ga = [a_group];

    // Posed successors naming the retired identity: fresh claims, OPL01.
    for (pred, what) in [
        (l1, "a CURRENT predecessor of the retired identity"),
        (
            l_world,
            "a current platform-corpus claim, owned by A's group",
        ),
        (
            l_world_retired,
            "a RETIRED platform-corpus claim, owned by A's group",
        ),
    ] {
        assert_opl01(
            pose_successor(&pool, x, &ga, legacy, a_group, pred).await,
            what,
        );
    }

    // The real supersede act still admits the inherited author, once.
    let s1 = as_app_stamped(&pool, x, &ga, |mut conn| async move {
        let r = {
            let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
            let r = epigraph_db::ClaimRepository::supersede_act_conn(
                &mut tx,
                epigraph_core::ClaimId::from_uuid(l1),
                "a revision of l1",
                epigraph_core::TruthValue::new(0.6).expect("truth"),
                "operator binding probe",
            )
            .await;
            if r.is_ok() {
                tx.commit().await.expect("commit");
            }
            r
        };
        (conn, r)
    })
    .await
    .expect("X supersedes its human's retired identity's claim")
    .0;
    assert_opl01(
        pose_successor(&pool, x, &ga, legacy, a_group, l1).await,
        "a second successor of an already-restated claim",
    );

    // No oracle: a predecessor in a group X cannot write is refused alike,
    // whoever authored it.
    for owner in [b_group, a_group] {
        let as_l = pose_successor(&pool, x, &ga, legacy, owner, l_in_b).await;
        let as_b = pose_successor(&pool, x, &ga, legacy, owner, b_in_b).await;
        assert!(as_l.is_err() && as_b.is_err(), "{as_l:?} / {as_b:?}");
        assert_eq!(
            code_of(&as_l),
            code_of(&as_b),
            "owner {owner}: the refusal must not depend on who authored the predecessor"
        );
    }

    // The admitted successor's lineage is not laundered.
    for (to, what) in [(None, "cleared"), (Some(l2), "re-pointed, still current")] {
        let r = as_app_stamped(&pool, x, &ga, |mut conn| async move {
            let r = sqlx::query("UPDATE claims SET supersedes = $2 WHERE id = $1")
                .bind(s1)
                .bind(to)
                .execute(&mut *conn)
                .await
                .map(|d| d.rows_affected());
            (conn, r)
        })
        .await;
        assert_eq!(code_of(&r).as_deref(), Some("OPL02"), "{what}: {r:?}");
    }
    let (sup, current): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(s1)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(
        (sup, current),
        (Some(l1), true),
        "the successor is unchanged"
    );
    let named: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE agent_id = $1")
        .bind(legacy)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(named, 6, "five seeded claims and the one real successor");

    // Controls: re-pointing while retiring (the dedup/consolidate shape) and a
    // privileged session are untouched.
    as_app_stamped(&pool, x, &ga, |mut conn| async move {
        let r = sqlx::query(
            "UPDATE claims SET supersedes = $2, is_current = false, embedding = NULL, \
                               embedding_3072 = NULL WHERE id = $1",
        )
        .bind(s1)
        .bind(x_claim)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await
    .expect("re-point while retiring");
    sqlx::query("UPDATE claims SET supersedes = NULL WHERE id = $1")
        .bind(s1)
        .execute(&pool)
        .await
        .expect("a privileged session may clear a lineage");
}

/// Delta review round 3 DIS-R3-1 (and the toggle SEC-R3-4 measured): the
/// inherited-author rules are not per-statement. A claim that becomes current
/// again on an application session is checked as if it were inserted now. So a
/// live agent cannot hold two current successors of one retired predecessor
/// under its human's retired identity by retiring the first, adding a second
/// and re-opening the first. Nor can it re-point a successor's lineage while
/// retiring it and then re-open it. The real shapes still work: an agent
/// re-opens its own claim, a successor whose predecessor has no other current
/// successor re-opens (it is inherited), and a privileged session re-opens
/// anything.
///
/// Verified to fail, each alone: `is_current` dropped from the trigger's column
/// list -> the toggled first successor re-opens ("two current successors");
/// the re-open branch disabled (`v_reopen` never set) -> the same.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_that_becomes_current_again_is_checked_as_an_insert(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "a-legacy").await;
    link_live(&pool, x, a).await;
    let l1 = insert_claim(&pool, legacy, a_group).await.expect("l1");
    let l2 = insert_claim(&pool, legacy, a_group).await.expect("l2");
    let x_claim = insert_claim(&pool, x, a_group).await.expect("X's claim");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_retired_agent(&mut conn, legacy, a)
            .await
            .expect("the legacy identity's retired tie to A");
    }
    assert!(arm(&pool).await, "the database arms");
    let ga = [a_group];
    // One UPDATE on X's application session, stamped with A's group.
    let update = |sql: &'static str, id: Uuid, other: Option<Uuid>| {
        let pool = pool.clone();
        async move {
            as_app_stamped(&pool, x, &[a_group], |mut conn| async move {
                let mut q = sqlx::query(sql).bind(id);
                if let Some(o) = other {
                    q = q.bind(o);
                }
                let r = q.execute(&mut *conn).await.map(|d| d.rows_affected());
                (conn, r)
            })
            .await
        }
    };
    let current_successors_of = |pred: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM claims WHERE supersedes = $1 AND agent_id = $2 \
                    AND COALESCE(is_current, true)",
            )
            .bind(pred)
            .bind(legacy)
            .fetch_one(&pool)
            .await
            .expect("count")
        }
    };
    const RETIRE: &str = "UPDATE claims SET is_current = false WHERE id = $1";
    const REOPEN: &str = "UPDATE claims SET is_current = true WHERE id = $1";

    // The real supersede act restates l1 under the retired identity: S1.
    let s1 = as_app_stamped(&pool, x, &ga, |mut conn| async move {
        let r = supersede_on(&mut conn, l1).await;
        (conn, r)
    })
    .await
    .expect("X supersedes its human's retired identity's claim")
    .0;

    // The toggle: retire S1, add a second successor S2, re-open S1.
    update(RETIRE, s1, None).await.expect("retire S1");
    let s2 = pose_successor(&pool, x, &ga, legacy, a_group, l1)
        .await
        .expect("S2: l1 has no current successor, so it is inherited");
    assert_opl01(
        update(REOPEN, s1, None).await.map(|_| s1),
        "re-opening S1 while S2 is l1's current successor",
    );
    assert_eq!(
        current_successors_of(l1).await,
        1,
        "two current successors of one retired predecessor under the retired identity"
    );

    // The two-step lineage: re-point S2 while retiring it (admitted, the
    // consolidate shape), then re-open it: l2 is current, so not inherited.
    update(
        "UPDATE claims SET supersedes = $2, is_current = false WHERE id = $1",
        s2,
        Some(l2),
    )
    .await
    .expect("re-point while retiring");
    assert_opl01(
        update(REOPEN, s2, None).await.map(|_| s2),
        "re-opening a successor whose lineage was re-pointed while retired",
    );
    let current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(s2)
        .fetch_one(&pool)
        .await
        .expect("read back");
    assert!(!current, "S2 stays retired");

    // Controls. l1 now has no current successor, so S1 re-opens as the one
    // inherited restatement it is; X re-opens its own claim; a privileged
    // session re-opens anything.
    update(REOPEN, s1, None)
        .await
        .expect("S1 re-opens: l1's one restatement");
    assert_eq!(current_successors_of(l1).await, 1);
    update(RETIRE, x_claim, None)
        .await
        .expect("X retires its claim");
    update(REOPEN, x_claim, None)
        .await
        .expect("X re-opens its own claim");
    sqlx::query(REOPEN)
        .bind(s2)
        .execute(&pool)
        .await
        .expect("a privileged session re-opens");
}

/// The supersede act on `conn`, in its own transaction, committed on success.
async fn supersede_on(
    conn: &mut sqlx::PgConnection,
    old: Uuid,
) -> Result<(Uuid, Uuid), epigraph_db::DbError> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
    let r = epigraph_db::ClaimRepository::supersede_act_conn(
        &mut tx,
        epigraph_core::ClaimId::from_uuid(old),
        &format!("custodial revision of {old}"),
        epigraph_core::TruthValue::new(0.6).expect("truth"),
        "operator binding probe",
    )
    .await;
    if r.is_ok() {
        tx.commit().await.expect("commit");
    }
    r
}

/// Delta review round 2 COR-R2-1 / DIS-R2-2: under the platform decision the
/// retired-linked and unlinked legacy rows stay world-owned, to be revised only
/// by an elevated act. Once armed, a PRIVILEGED (maintenance) session's
/// supersede of such a claim carries its predecessor's author whatever that
/// author's binding; before this, the author arm refused every one (OPL01).
/// Nothing else is relieved: a fresh claim, or a posed second successor,
/// naming an unbound author is still OPL01 on that session, and an
/// instance-admin PRINCIPAL (an application-session stamp) supersedes a
/// retired-linked author's world claim but not an unlinked one's.
///
/// Verified to fail: the author arm's `IF NOT (v_inherited AND
/// public.epigraph_bypass())` guard removed (require_bound_author always) ->
/// the maintenance session's supersedes are refused OPL01; the guard widened to
/// `v_inherited` alone -> the maintenance session still passes, and the
/// principal-equals-author control (the retired identity stamped as itself,
/// superseding its own retired world claim) lands; (round 3 COR-R3-6) the guard
/// widened to `v_inherited AND public.epigraph_operator_scope_exempt()` -> the
/// retired identity that is an instance admin, stamped as itself, lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_privileged_session_revises_the_platform_corpus_once_armed(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "a-legacy").await;
    let (unlinked, _) = fixture::seed_agent_with_group(&pool, "unlinked-legacy").await;
    let world = Uuid::nil();
    let mut corpus = Vec::new();
    for author in [legacy, unlinked, legacy, unlinked, legacy] {
        corpus.push(insert_claim(&pool, author, world).await.expect("corpus"));
    }
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_retired_agent(&mut conn, legacy, a)
            .await
            .expect("the legacy identity's retired tie to A");
    }
    sqlx::query(
        "INSERT INTO instance_admins (agent_id, note) VALUES ($1, 'operator binding test')",
    )
    .bind(a)
    .execute(&pool)
    .await
    .expect("A is an instance admin");
    arm(&pool).await;

    // The maintenance session revises both kinds of corpus claim.
    let (c_ret, c_unl) = (corpus[0], corpus[1]);
    let (revised, fresh, second) =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let revised = [
                supersede_on(&mut conn, c_ret).await,
                supersede_on(&mut conn, c_unl).await,
            ];
            let fresh = insert_claim(&mut *conn, unlinked, world).await;
            let id = Uuid::new_v4();
            let second = sqlx::query(
                "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                     visibility, owner_group_id, supersedes) \
                 VALUES ($1, 'posed second successor', $2, 0.5, $3, true, 'public', $4, $5)",
            )
            .bind(id)
            .bind(id.as_bytes().repeat(2))
            .bind(unlinked)
            .bind(world)
            .bind(c_unl)
            .execute(&mut *conn)
            .await
            .map(|_| id);
            (conn, (revised, fresh, second))
        })
        .await;
    for (r, author) in revised.into_iter().zip([legacy, unlinked]) {
        let (new, _) = r.unwrap_or_else(|e| panic!("maintenance supersede of {author}'s: {e:?}"));
        let row: (Uuid, Uuid) =
            sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE id = $1")
                .bind(new)
                .fetch_one(&pool)
                .await
                .expect("successor");
        assert_eq!(
            row,
            (author, world),
            "the successor inherits author and owner"
        );
    }
    assert_opl01(
        fresh,
        "a maintenance session's FRESH claim naming an unlinked author",
    );
    assert_opl01(second, "a maintenance session's posed second successor");

    // The retired identity stamped as ITSELF is the author arm on an
    // application session: never relieved.
    let (c_self, c_admin_ret, c_admin_unl) = (corpus[4], corpus[2], corpus[3]);
    let as_itself = as_app_stamped(&pool, legacy, &[world], |mut conn| async move {
        let r = supersede_on(&mut conn, c_self).await;
        (conn, r)
    })
    .await;
    assert!(
        matches!(
            as_itself,
            Err(epigraph_db::DbError::OperatorLinkRequired { .. })
        ),
        "the retired identity as its own principal: {as_itself:?}"
    );

    // An instance-admin principal: a retired-linked author's corpus claim,
    // yes; an unlinked author's, no (OPL01, documented). The stamp lists the
    // world group as writable so row security admits the retire half and the
    // trigger alone decides (whether a real admin viewer carries it is the
    // tenancy layer's question, not this one's).
    let admin = |old: Uuid| {
        let pool = pool.clone();
        async move {
            as_app_stamped(&pool, a, &[a_group, world], |mut conn| async move {
                let r = supersede_on(&mut conn, old).await;
                (conn, r)
            })
            .await
        }
    };
    admin(c_admin_ret)
        .await
        .expect("an instance admin revises a retired-linked author's corpus claim");
    let r = admin(c_admin_unl).await;
    assert!(
        matches!(r, Err(epigraph_db::DbError::OperatorLinkRequired { .. })),
        "an instance admin and an unlinked author's corpus claim: {r:?}"
    );

    // Round 3 COR-R3-6: the binding relief is the PRIVILEGED session's alone,
    // not every OPL02-exempt session's. A retired identity that is itself a live
    // instance admin (`instance_admins` is an ordinary table), stamped as
    // itself, restating its own retired corpus claim stays OPL01: the
    // instance-admin stamp exempts it from the cross-group scope, never from
    // the binding.
    sqlx::query("INSERT INTO instance_admins (agent_id, note) VALUES ($1, 'round 3 probe')")
        .bind(legacy)
        .execute(&pool)
        .await
        .expect("the retired identity is an instance admin");
    let admin_itself = as_app_stamped(&pool, legacy, &[world], |mut conn| async move {
        let r = supersede_on(&mut conn, c_self).await;
        (conn, r)
    })
    .await;
    assert!(
        matches!(
            admin_itself,
            Err(epigraph_db::DbError::OperatorLinkRequired { .. })
        ),
        "a retired identity that is an instance admin, as its own principal: {admin_itself:?}"
    );
}

/// Review SEC-10: the valve relieves the BINDING (OPL01) only. With it open, an
/// unbound agent writes, but a linked agent still cannot write into another
/// human's group and another human still cannot enrol it there (OPL02).
///
/// Verified to fail: `epigraph_require_writer_scope` gated on
/// `epigraph_operator_binding_enforced()` (the valve) instead of
/// `epigraph_operator_binding_armed()` -> Y's write into A's group lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_valve_relieves_the_binding_but_never_the_cross_human_scope(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, b_group) = fixture::seed_human_operator(&pool, "human-b").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "b-agent-y").await;
    let (u, u_group) = fixture::seed_agent_with_group(&pool, "unbound-u").await;
    link_live(&pool, x, a).await;
    link_live(&pool, y, b).await;
    arm(&pool).await;

    let valve_write = |writer: Uuid, groups: Vec<Uuid>, author: Uuid, owner: Uuid| {
        let pool = pool.clone();
        async move {
            as_app_stamped(&pool, writer, &groups, |mut conn| async move {
                sqlx::query(
                    "SELECT set_config('epigraph.operator_link_enforcement', 'off', false)",
                )
                .execute(&mut *conn)
                .await
                .expect("valve");
                let r = insert_claim(&mut *conn, author, owner).await;
                sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
                    .execute(&mut *conn)
                    .await
                    .expect("valve reset");
                (conn, r)
            })
            .await
        }
    };
    valve_write(u, vec![u_group], u, u_group)
        .await
        .expect("the valve admits an unbound author (its purpose)");
    let r = valve_write(y, vec![a_group], y, a_group).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some("OPL02"),
        "valve open, Y into A's group: {r:?}"
    );

    let enrol = as_app_stamped(&pool, b, &[b_group], |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', 'off', false)")
            .execute(&mut *conn)
            .await
            .expect("valve");
        let r = sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(b_group)
        .bind(x)
        .execute(&mut *conn)
        .await;
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
            .execute(&mut *conn)
            .await
            .expect("valve reset");
        (conn, r)
    })
    .await;
    assert_eq!(
        code_of(&enrol).as_deref(),
        Some("OPL02"),
        "valve open, B enrols X: {enrol:?}"
    );
}

/// Delta review SEC-D2 / COR-D7 / DIS-D4: with the valve open, an UNBOUND
/// writer (stamped honestly as itself, writing into its own group) may still
/// author only as itself or as another unbound identity. Naming a human, or a
/// human's agent, is a cross-human attribution the valve never relieves
/// (OPL02, keyed on the arming). The owner group is the writer's own, so row
/// security admits every arm and the trigger alone decides.
///
/// Verified to fail: `epigraph_require_attributable` returning early when the
/// writer's human is NULL (the pre-fix `IF v_writer_human IS NULL OR ...`) ->
/// U's claims naming human A and B's agent Y land.
#[sqlx::test(migrations = "../../migrations")]
async fn the_valve_never_lets_an_unbound_writer_name_a_bound_author(pool: PgPool) {
    let (a, _) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "human-b").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "b-agent-y").await;
    let (u, u_group) = fixture::seed_agent_with_group(&pool, "unbound-u").await;
    let (v, _) = fixture::seed_agent_with_group(&pool, "unbound-v").await;
    link_live(&pool, y, b).await;
    arm(&pool).await;

    let valve_write = |author: Uuid| {
        let pool = pool.clone();
        async move {
            as_app_stamped(&pool, u, &[u_group], |mut conn| async move {
                sqlx::query(
                    "SELECT set_config('epigraph.operator_link_enforcement', 'off', false)",
                )
                .execute(&mut *conn)
                .await
                .expect("valve");
                let r = insert_claim(&mut *conn, author, u_group).await;
                sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
                    .execute(&mut *conn)
                    .await
                    .expect("valve reset");
                (conn, r)
            })
            .await
        }
    };

    for (author, what) in [
        (a, "valve open, unbound U names human A"),
        (y, "valve open, unbound U names B's live agent Y"),
    ] {
        let r = valve_write(author).await;
        assert_eq!(code_of(&r).as_deref(), Some("OPL02"), "{what}: {r:?}");
    }
    let named: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE owner_group_id = $1 AND agent_id <> $2",
    )
    .bind(u_group)
    .bind(u)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(named, 0, "an unbound writer attributed {named} claim(s)");

    // Controls: the valve's purpose (an unbound writer as itself, or naming
    // another unbound identity) is untouched.
    valve_write(u).await.expect("valve open, U as itself");
    valve_write(v)
        .await
        .expect("valve open, U names another unbound agent");
}

/// Delta review round 2 SEC-R2-1: workflow ingest writes every row as ONE
/// shared system identity under that identity's own stamp, so the claims
/// trigger sees writer = author = the system agent and the request path binds
/// its real CALLER in Rust (`AgentRepository::require_writer_authority`). With
/// the valve open, the binding half is relieved and the scope half is quiet for
/// a caller that belongs to no human, so an unbound caller (or no caller) put
/// its text into the human's group as the live-linked system identity. The
/// attribution half (OPL02, keyed on the arming) must refuse it whatever the
/// valve. Measured on the application role, stamped as the system identity,
/// exactly as the workflow paths stamp it.
///
/// Verified to fail: the `epigraph_require_attributable` call dropped from
/// `require_writer_authority`'s statement -> the unbound and absent callers are
/// admitted with the valve open.
#[sqlx::test(migrations = "../../migrations")]
async fn the_workflow_caller_check_holds_with_the_valve_open(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "human-b").await;
    let (system, _) = fixture::seed_agent_with_group(&pool, "shared-system").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "b-agent-y").await;
    let (u, _) = fixture::seed_agent_with_group(&pool, "unbound-u").await;
    link_live(&pool, system, a).await;
    link_live(&pool, x, a).await;
    link_live(&pool, y, b).await;
    arm(&pool).await;

    let check = |caller: Option<Uuid>, valve_off: bool| {
        let pool = pool.clone();
        async move {
            as_app_stamped(&pool, system, &[a_group], |mut conn| async move {
                let v = if valve_off { "off" } else { "" };
                sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', $1, false)")
                    .bind(v)
                    .execute(&mut *conn)
                    .await
                    .expect("valve");
                let r =
                    AgentRepository::require_writer_authority(&mut conn, system, caller, a_group)
                        .await;
                sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
                    .execute(&mut *conn)
                    .await
                    .expect("valve reset");
                (conn, r)
            })
            .await
        }
    };

    for (caller, what) in [
        (Some(u), "valve open, unbound caller"),
        (None, "valve open, no caller"),
        (Some(y), "valve open, another human's caller"),
    ] {
        let r = check(caller, true).await;
        assert!(
            matches!(r, Err(epigraph_db::DbError::OperatorScopeRefused { .. })),
            "{what}: expected OPL02, got {r:?}"
        );
    }
    let r = check(Some(u), false).await;
    assert!(
        matches!(r, Err(epigraph_db::DbError::OperatorLinkRequired { .. })),
        "valve closed, unbound caller: expected OPL01, got {r:?}"
    );

    // Controls: callers that belong to the system agent's human.
    for (caller, what) in [(x, "A's agent X"), (a, "human A")] {
        check(Some(caller), true)
            .await
            .unwrap_or_else(|e| panic!("valve open, {what}: {e:?}"));
        check(Some(caller), false)
            .await
            .unwrap_or_else(|e| panic!("valve closed, {what}: {e:?}"));
    }
}

/// Delta review round 2 DIS-R2-1: a RETIRED identity still belongs to its
/// human. With the valve open, neither an unbound writer nor another human's
/// agent may name it (OPL02, keyed on the arming), which the live-only lookup
/// missed: the author "belonged to no human", took the binding branch, and the
/// valve relieved that. With the valve closed another human's agent is refused
/// OPL02 too (it was OPL01). The writer's OWN human's retired identity on a
/// fresh claim stays OPL01, which the valve relieves (one human, no crossing).
///
/// Verified to fail: `epigraph_require_attributable`'s any-state lookup
/// removed (the `IF v_author_human IS NULL THEN` branch back to a bare
/// `epigraph_require_bound_author` + RETURN) -> U's and Y's valve-open claims
/// naming A's retired identity land.
#[sqlx::test(migrations = "../../migrations")]
async fn no_valve_lets_a_writer_outside_its_human_name_a_retired_identity(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, b_group) = fixture::seed_human_operator(&pool, "human-b").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "b-agent-y").await;
    let (u, u_group) = fixture::seed_agent_with_group(&pool, "unbound-u").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "a-legacy").await;
    link_live(&pool, x, a).await;
    link_live(&pool, y, b).await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_retired_agent(&mut conn, legacy, a)
            .await
            .expect("the legacy identity's retired tie to A");
    }
    arm(&pool).await;

    let write = |writer: Uuid, group: Uuid, valve_off: bool| {
        let pool = pool.clone();
        async move {
            as_app_stamped(&pool, writer, &[group], |mut conn| async move {
                let v = if valve_off { "off" } else { "" };
                sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', $1, false)")
                    .bind(v)
                    .execute(&mut *conn)
                    .await
                    .expect("valve");
                let r = insert_claim(&mut *conn, legacy, group).await;
                sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
                    .execute(&mut *conn)
                    .await
                    .expect("valve reset");
                (conn, r)
            })
            .await
        }
    };

    for (writer, group, valve_off, what) in [
        (
            u,
            u_group,
            true,
            "valve open, unbound U names A's retired identity",
        ),
        (
            y,
            b_group,
            true,
            "valve open, B's agent Y names A's retired identity",
        ),
        (
            y,
            b_group,
            false,
            "valve closed, B's agent Y names A's retired identity",
        ),
    ] {
        let r = write(writer, group, valve_off).await;
        assert_eq!(code_of(&r).as_deref(), Some("OPL02"), "{what}: {r:?}");
    }
    let named: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE agent_id = $1")
        .bind(legacy)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        named, 0,
        "{named} claim(s) attributed to the retired identity"
    );

    // Controls. Within A's own human a fresh claim naming its retired identity
    // is OPL01 with the valve closed, and relieved by the valve (no crossing).
    assert_opl01(
        write(x, a_group, false).await,
        "valve closed, A's agent X names A's retired identity",
    );
    write(x, a_group, true)
        .await
        .expect("valve open, A's agent X names its own human's retired identity");
}

/// Delta review round 3 SEC-R3-2: with the valve open, a RETIRED identity is
/// still scoped by its human. Stamped as itself, or named on an unstamped
/// application session, it does not write into another human's group or into
/// the world group (OPL02, from the trigger, before row security). Within its
/// own human the valve still relieves it.
///
/// Verified to fail: `epigraph_require_writer_scope` reading the live link only
/// (`epigraph_human_of(p_agent, true)`, the round-2 body) -> the retired
/// identity stamped as itself writes into B's group.
#[sqlx::test(migrations = "../../migrations")]
async fn the_valve_never_lets_a_retired_identity_write_outside_its_human(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (_b, b_group) = fixture::seed_human_operator(&pool, "human-b").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "a-legacy").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_retired_agent(&mut conn, legacy, a)
            .await
            .expect("the legacy identity's retired tie to A");
    }
    let world = fixture::world_group(&pool).await;
    assert!(arm(&pool).await, "the database arms");

    // An application session with the valve OFF and `group` stamped readable
    // and writable (so row security admits the row), stamped as `principal`
    // or with no principal at all; it names the retired identity as author.
    let write = |principal: Option<Uuid>, group: Uuid| {
        let pool = pool.clone();
        async move {
            fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
                sqlx::query(
                    "SELECT set_config('epigraph.principal_id', $1, false), \
                            set_config('epigraph.group_ids', $2, false), \
                            set_config('epigraph.writable_group_ids', $2, false), \
                            set_config('epigraph.operator_link_enforcement', 'off', false)",
                )
                .bind(principal.map(|p| p.to_string()).unwrap_or_default())
                .bind(group.to_string())
                .execute(&mut *conn)
                .await
                .expect("stamp, valve off");
                let r = insert_claim(&mut *conn, legacy, group).await;
                sqlx::query(
                    "SELECT set_config('epigraph.principal_id', '', false), \
                            set_config('epigraph.group_ids', '', false), \
                            set_config('epigraph.writable_group_ids', '', false), \
                            set_config('epigraph.operator_link_enforcement', '', false)",
                )
                .execute(&mut *conn)
                .await
                .expect("unstamp");
                (conn, r)
            })
            .await
        }
    };

    for (principal, group, what) in [
        (
            Some(legacy),
            b_group,
            "the retired identity as itself, into B's group",
        ),
        (
            None,
            b_group,
            "unstamped, naming the retired identity, into B's group",
        ),
        (
            Some(legacy),
            world,
            "the retired identity as itself, into the world group",
        ),
        (
            None,
            world,
            "unstamped, naming the retired identity, into the world group",
        ),
    ] {
        let r = write(principal, group).await;
        assert_eq!(code_of(&r).as_deref(), Some("OPL02"), "{what}: {r:?}");
    }
    let named: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE agent_id = $1")
        .bind(legacy)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(named, 0, "{named} claim(s) by the retired identity landed");

    // Controls: inside its own human the valve relieves it, stamped or not.
    write(Some(legacy), a_group)
        .await
        .expect("valve open, the retired identity as itself into its human's group");
    write(None, a_group)
        .await
        .expect("valve open, unstamped, the retired identity into its human's group");
}

/// Delta review SEC-D5: the checks read the NEW author only, so an UPDATE of
/// `claims.agent_id` must not be a way to take over a claim another human
/// said. Human B also writes A's group; B's claim sits there; A's live agent X,
/// stamped honestly with that group writable, tries to make the claim its own.
/// Refused (OPL02) on the application role; a privileged session still may
/// (and is checked like an insert: `an_update_that_hands_a_claim_to_an_unbound_author_is_refused`).
///
/// Verified to fail: the trigger's `TG_OP = 'UPDATE' AND NOT
/// epigraph_operator_scope_exempt()` refusal removed -> B's claim becomes X's.
#[sqlx::test(migrations = "../../migrations")]
async fn an_application_session_never_re_attributes_a_claim(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "human-b").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    link_live(&pool, x, a).await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(a_group)
    .bind(b)
    .execute(&pool)
    .await
    .expect("B also writes A's group");
    let b_claim = insert_claim(&pool, b, a_group)
        .await
        .expect("B's claim in the shared group");
    let x_claim = insert_claim(&pool, x, a_group).await.expect("X's claim");
    arm(&pool).await;

    let take = as_app_stamped(&pool, x, &[a_group], |mut conn| async move {
        let r = sqlx::query("UPDATE claims SET agent_id = $2 WHERE id = $1")
            .bind(b_claim)
            .bind(x)
            .execute(&mut *conn)
            .await
            .map(|d| d.rows_affected());
        (conn, r)
    })
    .await;
    assert_eq!(
        code_of(&take).as_deref(),
        Some("OPL02"),
        "X took over B's claim: {take:?}"
    );
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(b_claim)
        .fetch_one(&pool)
        .await
        .expect("author");
    assert_eq!(author, b, "B's claim is still B's");

    // Control: an update that leaves the author alone is untouched.
    as_app_stamped(&pool, x, &[a_group], |mut conn| async move {
        let r = sqlx::query("UPDATE claims SET truth_value = 0.6 WHERE id = $1")
            .bind(x_claim)
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await
    .expect("X re-scores its own claim");
}

/// Delta review SEC-D1 / DIS-D1 (the database half): an APPLICATION session
/// with no principal stamped (a route that wrote on the raw pool) is an
/// unbound writer, not a licence to be checked on the author column alone.
/// Measured in the shape a long-lived deployment may carry: the orphan permissive `claims_privacy`
/// policy (`FOR ALL USING (true)`, no `WITH CHECK`, standing in for the one no
/// migration creates) is installed, so row security admits the unstamped
/// INSERT and only the trigger can refuse it.
///
/// Verified to fail: the trigger's `v_writer IS NULL AND NOT epigraph_bypass()
/// AND epigraph_operator_binding_enforced()` refusal removed -> the unstamped
/// claims attributed to human A and to A's agent X land in A's group.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unstamped_application_session_writes_no_claim_once_armed(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    link_live(&pool, x, a).await;
    sqlx::query("CREATE POLICY claims_privacy ON claims FOR ALL USING (true)")
        .execute(&pool)
        .await
        .expect("the orphan permissive policy (a deployment shape)");
    arm(&pool).await;

    let unstamped = |author: Uuid, valve_off: bool| {
        let pool = pool.clone();
        async move {
            fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
                let principal: Option<String> =
                    sqlx::query_scalar("SELECT public.epigraph_principal_id()::text")
                        .fetch_one(&mut *conn)
                        .await
                        .expect("principal");
                assert_eq!(principal, None, "this session must carry no principal");
                if valve_off {
                    sqlx::query(
                        "SELECT set_config('epigraph.operator_link_enforcement', 'off', false)",
                    )
                    .execute(&mut *conn)
                    .await
                    .expect("valve");
                }
                let r = insert_claim(&mut *conn, author, a_group).await;
                sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
                    .execute(&mut *conn)
                    .await
                    .expect("valve reset");
                (conn, r)
            })
            .await
        }
    };

    for (author, what) in [
        (a, "unstamped app session names human A in A's group"),
        (x, "unstamped app session names A's agent X in A's group"),
    ] {
        let r = unstamped(author, false).await;
        assert_opl01(r, what);
    }
    let written: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE owner_group_id = $1")
        .bind(a_group)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(written, 0, "an unstamped session wrote {written} claim(s)");

    // The valve relieves exactly that OPL01 (and then the author is checked).
    unstamped(a, true)
        .await
        .expect("valve open: the unstamped write is checked on its author");
}

/// Review SEC-6 / SEC-8: a human is the agent of the ONE client its
/// registration names, so the application role (which may INSERT
/// `oauth_clients`, but not UPDATE it) cannot undo a suspension by minting a
/// fresh active human client; and the registry's rules hold for a direct
/// maintenance write: a revoke is final (no un-revoke by UPDATE), an INSERT for
/// an agent with no active human client is refused, and a direct INSERT is
/// audited like the definer's.
///
/// Verified to fail, each alone: `epigraph_is_human_operator` reading any
/// active human client of the agent (not `h.client_id`) -> the minted client
/// revives B's agent; the `human_operators_guard_update` trigger dropped -> the
/// un-revoke lands; the `human_operators_audit` trigger dropped -> the direct
/// INSERT leaves no audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_registry_keys_on_its_client_and_holds_for_direct_writes(pool: PgPool) {
    let (b, _) = fixture::seed_human_operator(&pool, "human-b").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "b-agent-y").await;
    link_live(&pool, y, b).await;
    let binding = |agent: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>("SELECT public.epigraph_author_binding($1)")
                .bind(agent)
                .fetch_one(&pool)
                .await
                .expect("binding")
        }
    };
    assert_eq!(binding(y).await.as_deref(), Some("live_link"));

    sqlx::query("UPDATE oauth_clients SET status = 'suspended' WHERE agent_id = $1")
        .bind(b)
        .execute(&pool)
        .await
        .expect("suspend B's recorded client");
    assert_eq!(binding(y).await, None, "a suspended client binds nobody");
    fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                        status, agent_id) \
             VALUES ($1, 'minted', 'human', ARRAY['claims:write'], 'active', $2)",
        )
        .bind(format!("minted-{b}"))
        .bind(b)
        .execute(&mut *conn)
        .await
        .expect("the app role may register a client");
        (conn, ())
    })
    .await;
    assert_eq!(
        binding(y).await,
        None,
        "a freshly minted active human client must not revive a suspended human"
    );

    // Revoke through the definer, then try to un-revoke directly.
    let (unrevoke, no_client_insert, direct_ok) =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'test')")
                .bind(b)
                .execute(&mut *conn)
                .await
                .expect("revoke");
            let unrevoke = sqlx::query(
                "UPDATE human_operators SET revoked_at = NULL, revoked_by = NULL, \
                        revoked_reason = NULL WHERE agent_id = $1",
            )
            .bind(b)
            .execute(&mut *conn)
            .await
            .err()
            .and_then(|e| sqlstate(&e));
            let (bare, _) = (Uuid::new_v4(), ());
            sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'human')")
                .bind(bare)
                .bind(bare.as_bytes().repeat(2))
                .execute(&mut *conn)
                .await
                .expect("bare agent");
            let no_client =
                sqlx::query("INSERT INTO human_operators (agent_id, reason) VALUES ($1, 'direct')")
                    .bind(bare)
                    .execute(&mut *conn)
                    .await
                    .err()
                    .and_then(|e| sqlstate(&e));
            (conn, (unrevoke, no_client, bare))
        })
        .await;
    assert_eq!(unrevoke.as_deref(), Some("55000"), "revoke is final");
    assert_eq!(
        no_client_insert.as_deref(),
        Some("55000"),
        "no active human client"
    );
    let _ = direct_ok;
    let human: bool = sqlx::query_scalar("SELECT public.epigraph_is_human_operator($1)")
        .bind(b)
        .fetch_one(&pool)
        .await
        .expect("is human");
    assert!(!human, "B stays revoked");

    // A direct maintenance INSERT for a real human client is audited.
    let (c, _) = fixture::seed_agent_with_group(&pool, "human-c").await;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, 'c', 'human', ARRAY['claims:write'], 'active', $2)",
    )
    .bind(format!("c-{c}"))
    .bind(c)
    .execute(&pool)
    .await
    .expect("C's client");
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("INSERT INTO human_operators (agent_id, reason) VALUES ($1, 'direct')")
            .bind(c)
            .execute(&mut *conn)
            .await
            .expect("a direct maintenance registration of a real human client");
        (conn, ())
    })
    .await;
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = 'operator.human_registered' AND agent_id = $1",
    )
    .bind(c)
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(
        audited, 1,
        "a direct registration is audited like the definer's"
    );
}

/// Delta review round 3 SEC-R3-1: the application role cannot take an OAuth
/// client back out of `suspended` or `revoked` through 118's approval definer
/// (the REST admin approval, which it may EXECUTE). So a human whose recorded
/// client a maintenance session suspended stays un-registered, and that human's
/// live agent stays refused. A revoked client stays revoked too. Promoting a
/// `pending` client on the application role and re-activating on a privileged
/// session both still work.
///
/// Verified to fail: the `oauth_clients_reactivation_guard` trigger dropped ->
/// the application role's approval re-activates B's suspended client, and Y is
/// `live_link` again ("re-activated a suspended client").
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_privileged_session_reactivates_a_suspended_or_revoked_client(pool: PgPool) {
    let (b, b_group) = fixture::seed_human_operator(&pool, "human-b").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "b-agent-y").await;
    link_live(&pool, y, b).await;
    assert!(arm(&pool).await, "the database arms");
    let recorded: Uuid =
        sqlx::query_scalar("SELECT client_id FROM human_operators WHERE agent_id = $1")
            .bind(b)
            .fetch_one(&pool)
            .await
            .expect("B's recorded client");
    let binding = |agent: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>("SELECT public.epigraph_author_binding($1)")
                .bind(agent)
                .fetch_one(&pool)
                .await
                .expect("binding")
        }
    };
    let status_of = |client: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT status FROM oauth_clients WHERE id = $1")
                .bind(client)
                .fetch_one(&pool)
                .await
                .expect("status")
        }
    };
    let app_approve = |client: Uuid| {
        let pool = pool.clone();
        async move {
            fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
                let r = sqlx::query_scalar::<_, bool>(
                    "SELECT public.epigraph_oauth_client_approve($1, ARRAY['claims:write'], NULL)",
                )
                .bind(client)
                .fetch_one(&mut *conn)
                .await;
                (conn, r)
            })
            .await
        }
    };
    assert_eq!(binding(y).await.as_deref(), Some("live_link"));

    for from in ["suspended", "revoked"] {
        // The maintenance act (here the superuser harness, a privileged session).
        sqlx::query("UPDATE oauth_clients SET status = $2 WHERE id = $1")
            .bind(recorded)
            .bind(from)
            .execute(&pool)
            .await
            .expect("take B's recorded client out of service");
        assert_eq!(binding(y).await, None, "{from}: B is no longer a human");
        let r = app_approve(recorded).await;
        assert!(
            r.is_err(),
            "{from}: the application role re-activated a {from} client: {r:?}"
        );
        assert_eq!(
            code_of(&r).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{from}: expected 42501, got {r:?}"
        );
        assert_eq!(status_of(recorded).await, from, "{from}: the status stays");
        assert_eq!(
            binding(y).await,
            None,
            "{from}: B's agent stays unbound after the refused approval"
        );
        let w = write_as(&pool, y, &[b_group], y, b_group).await;
        assert_eq!(
            code_of(&w).as_deref(),
            Some(OPL01),
            "{from}: B's agent writes nothing: {w:?}"
        );
    }

    // Control: the application role still promotes a PENDING client.
    let pending = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                    status) \
         VALUES ($1, $2, 'pending', 'human', ARRAY['claims:read'], 'pending')",
    )
    .bind(pending)
    .bind(format!("pending-{pending}"))
    .execute(&pool)
    .await
    .expect("a pending client");
    let r = app_approve(pending).await;
    assert!(matches!(r, Ok(true)), "a pending client is approved: {r:?}");
    assert_eq!(status_of(pending).await, "active");

    // Control: a privileged session re-activates, and B is a human again.
    sqlx::query("UPDATE oauth_clients SET status = 'active' WHERE id = $1")
        .bind(recorded)
        .execute(&pool)
        .await
        .expect("a privileged re-activation");
    assert_eq!(binding(y).await.as_deref(), Some("live_link"));
}

/// Review SEC-12 / SEC-5: every link row is audited where it is written, and
/// OPERATED_BY edges an application session forges FROM a human no longer
/// block linking agents to that human (107's operator-side fingerprint is
/// skipped for a registered human operator).
///
/// Verified to fail, each alone: the `operator_links_audit` trigger dropped ->
/// no `operator.link_recorded` row; section 9's `NOT
/// public.epigraph_is_human_operator(p_operator) AND` removed from
/// `epigraph_link_operator` -> the link after the forgery is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn links_are_audited_and_forged_edges_cannot_block_a_human(pool: PgPool) {
    let (a, _) = fixture::seed_human_operator(&pool, "human-a").await;
    let (u, u_group) = fixture::seed_agent_with_group(&pool, "unbound-u").await;
    let (p, _) = fixture::seed_agent_with_group(&pool, "principal-p").await;
    let (fleet, _) = fixture::seed_agent_with_group(&pool, "new-fleet-agent").await;
    let (legacy, legacy_group) = fixture::seed_agent_with_group(&pool, "legacy").await;
    insert_claim(&pool, legacy, legacy_group)
        .await
        .expect("legacy claim");

    as_app_stamped(&pool, u, &[u_group], |mut conn| async move {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'agent', $2, 'agent', 'OPERATED_BY'), \
                    ($1, 'agent', $3, 'agent', 'OPERATED_BY')",
        )
        .bind(a)
        .bind(u)
        .bind(p)
        .execute(&mut *conn)
        .await
        .expect("an app session can write these edges");
        (conn, ())
    })
    .await;

    link_live(&pool, fleet, a).await;
    link_live(&pool, fleet, a).await; // an exact re-link records nothing new
    let linked: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT * FROM public.epigraph_link_legacy_authors($1)")
            .bind(a)
            .fetch_all(&pool)
            .await
            .expect("the legacy tie is not refused either");
    assert!(
        linked.contains(&(legacy, "linked".to_string())),
        "{linked:?}"
    );

    let events: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT agent_id, details->>'retired' FROM security_events \
          WHERE event_type = 'operator.link_recorded' ORDER BY created_at, agent_id",
    )
    .fetch_all(&pool)
    .await
    .expect("link events");
    assert!(events.contains(&(fleet, "false".to_string())), "{events:?}");
    assert!(events.contains(&(legacy, "true".to_string())), "{events:?}");
    assert_eq!(
        events.iter().filter(|(agent, _)| *agent == fleet).count(),
        1,
        "one event per recorded link, none for a re-link"
    );
}

/// Reviews C6 / SEC-11, C7 and C8 (the `foreign_write_authority` survivor):
/// `epigraph_link_legacy_authors` never ties an agent whose own auth lineage
/// names ANOTHER registered human, nor one that writes in a group this operator
/// does not write; and it counts `challenges.resolved_by` as authorship.
///
/// Verified to fail, each alone: the `skipped:operated_by_other_human` arm
/// deleted -> B's agent is tied to A; the `skipped:foreign_write_authority` arm
/// deleted -> the foreign writer is tied to A; the `challenges.resolved_by`
/// UNION arm deleted -> the resolver is not a candidate.
#[sqlx::test(migrations = "../../migrations")]
async fn the_legacy_tie_never_takes_another_humans_agent(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, b_group) = fixture::seed_human_operator(&pool, "human-b").await;
    let (of_b, of_b_group) = fixture::seed_agent_with_group(&pool, "b-lineage").await;
    let (foreign, foreign_group) = fixture::seed_agent_with_group(&pool, "b-writer").await;
    let (plain, plain_group) = fixture::seed_agent_with_group(&pool, "plain").await;
    let (resolver, _) = fixture::seed_agent_with_group(&pool, "resolver").await;
    for (agent, group) in [
        (of_b, of_b_group),
        (foreign, foreign_group),
        (plain, plain_group),
    ] {
        insert_claim(&pool, agent, group)
            .await
            .expect("legacy claim");
    }
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'agent', $2, 'agent', 'OPERATED_BY')",
    )
    .bind(of_b)
    .bind(b)
    .execute(&pool)
    .await
    .expect("lineage to B");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(b_group)
    .bind(foreign)
    .execute(&pool)
    .await
    .expect("a writer row in B's group");
    let a_claim = insert_claim(&pool, a, a_group).await.expect("A's claim");
    sqlx::query(
        "INSERT INTO challenges (claim_id, challenge_type, explanation, resolved_by, state) \
         VALUES ($1, 'factual', 'resolved', $2, 'resolved')",
    )
    .bind(a_claim)
    .bind(resolver)
    .execute(&pool)
    .await
    .expect("a challenge resolved by the resolver");

    let outcomes: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT * FROM public.epigraph_link_legacy_authors($1)")
            .bind(a)
            .fetch_all(&pool)
            .await
            .expect("legacy tie");
    let outcome = |agent: Uuid| {
        outcomes
            .iter()
            .find(|(id, _)| *id == agent)
            .map(|(_, o)| o.clone())
    };
    assert_eq!(
        outcome(of_b).as_deref(),
        Some("skipped:operated_by_other_human"),
        "{outcomes:?}"
    );
    assert_eq!(
        outcome(foreign).as_deref(),
        Some("skipped:foreign_write_authority"),
        "{outcomes:?}"
    );
    assert_eq!(outcome(plain).as_deref(), Some("linked"), "{outcomes:?}");
    assert_eq!(outcome(resolver).as_deref(), Some("linked"), "{outcomes:?}");
    let tied_to_a: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM operator_links WHERE operator_id = $1 AND agent_id IN ($2, $3)",
    )
    .bind(a)
    .bind(of_b)
    .bind(foreign)
    .fetch_one(&pool)
    .await
    .expect("links");
    assert_eq!(tied_to_a, 0, "neither is tied to A");
}
