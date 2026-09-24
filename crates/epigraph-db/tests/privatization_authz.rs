//! PR-18a: who is allowed to privatize, and can the authority actually be
//! granted?
//!
//! # The acceptance clauses this shard discharges
//!
//! `docs/tenancy/FINAL-PLAN.md`'s PR-18 acceptance list has **ten** clauses, not
//! thirteen — re-counted by splitting that line on `;`. An earlier revision of
//! this comment said thirteen and then reasoned from the wrong number about what
//! the rest of the list contains, which is the drift this file's own calibration
//! assertions exist to refuse. Clause 7 is this file's subject in full:
//!
//! > `instance_admins` is empty after migration and every privatization attempt
//! > 403s until an operator grants.
//!
//! Clause 5's database half — a target group younger than 24 h, or with fewer
//! than two other live admins — ships in migration 081's plan guard and is
//! asserted below. The HTTP-403 half of clause 5, and clauses 1, 2, 3, 4, 6, 8,
//! 9 and 10, are PR-18b's and PR-18c's.
//!
//! Half of that clause is trivially true of a table nobody writes. The half
//! worth testing is the OTHER half — that an operator CAN grant — because a
//! grant path that fails closed satisfies "empty after migration" perfectly and
//! makes the clause undeliverable.
//!
//! # THE VACUITY PROBLEM, RESTATED FOR THIS FILE
//!
//! `DATABASE_URL` is `epigraph`: `rolsuper`, `rolbypassrls`, and the owner of
//! every table here. `BYPASSRLS` defeats `FORCE ROW LEVEL SECURITY` outright, so
//! **a grant test written on the default pool passes against a policy set that
//! has no write policy at all** — measured, and it is exactly the shape this
//! file was written to catch. Every write assertion below therefore runs on
//! `viewer_fixture::downgraded_pool`, whose `after_connect` issues
//! `SET SESSION AUTHORIZATION`, which changes `session_user` — the value
//! `epigraph_bypass()` reads — and confers no `BYPASSRLS`.
//! `epigraph_maintenance` is `rolsuper=f rolbypassrls=f`, so the policy is the
//! only thing that can admit the write.
//!
//! Each positive is paired with the same call on `epigraph_app`, which must
//! fail. A file of positives alone is satisfied by a policy that admits
//! everybody.
//!
//! # What is deliberately NOT here
//!
//! The plan's other six privatization test files — closure, hull, resume,
//! revert, drift — are 18b's and 18c's. They measure a selection pass and an
//! apply handler, and PR-18a ships neither; written now they would assert over
//! empty tables, which is the failure mode this suite exists to refuse.
//! `privatization_boundary.rs` already exists and is PR-13's.

mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

use epigraph_db::repos::instance_admin::InstanceAdminRepository;
use epigraph_db::repos::privatization::{
    PrivatizationRepository, SelectionError, SelectionRefusal,
};

/// **The acceptance clause, first half.** Migration 083 seeds nothing, and
/// nobody is an instance administrator at head.
///
/// The second assertion is not a restatement of the first. An empty table with a
/// predicate that answered `true` on absence — `NOT EXISTS(... revoked_at IS NOT
/// NULL)`, say — would satisfy the count and grant the authority to the whole
/// world, which is the D1 failure ("nothing is authorized by absence") in its
/// most direct form. So the predicate is asked separately, about a real agent.
#[sqlx::test(migrations = "../../migrations")]
async fn instance_admins_is_empty_after_migration_and_the_predicate_says_no(pool: PgPool) {
    let count: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM instance_admins")
        .fetch_one(&pool)
        .await
        .expect("count instance_admins");
    assert_eq!(
        count, 0,
        "migration 083 must seed nothing. An empty instance_admins means nobody can privatize, \
         which is the correct fail-closed initial state for a corpus that starts public."
    );

    let (agent, _group) = fixture::seed_agent_with_group(&pool, "nobody").await;
    assert!(
        !InstanceAdminRepository::is_active(&pool, agent)
            .await
            .expect("is_active"),
        "an agent with no row must not be an instance administrator"
    );
    // And the absence is not merely "no row for this agent": the NIL uuid, which
    // is what a caller with no principal would supply, is also refused.
    assert!(
        !InstanceAdminRepository::is_active(&pool, Uuid::nil())
            .await
            .expect("is_active(nil)"),
        "the nil principal must not be an instance administrator"
    );
}

/// **The acceptance clause, second half.** An operator on `epigraph_maintenance`
/// can grant and revoke; an app connection cannot.
///
/// This is the assertion that would have caught the defect this file was
/// written for. `instance_admins` is `ENABLE` + `FORCE`, and a policy set with
/// no INSERT policy denies the INSERT to every role including the owner —
/// `epigraph_bypass()` cannot help, because it is a predicate that lives inside
/// a policy and there is nothing for it to appear in. On the default superuser
/// pool the grant succeeds regardless, so the whole clause would have read green
/// over an operator action that fails closed with `42501` the moment
/// `MAINTENANCE_DATABASE_URL` stops being a superuser — which is precisely the
/// posture plan §9.2 step 11d prescribes.
///
/// `grant_app_privileges` is deliberately NOT called. Migration 083 issues the
/// grants it intends, and re-granting here would paper over exactly the REVOKE
/// that is half the control.
#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_can_grant_on_the_maintenance_role_and_the_app_role_cannot(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "grantee").await;
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;

    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;

    // CALIBRATION. The downgraded pool is really downgraded — if this said
    // `epigraph` the whole test would be the vacuous one it exists to replace.
    let (session_user, bypassrls): (String, bool) = sqlx::query_as(
        "SELECT session_user::text, \
                (SELECT r.rolbypassrls FROM pg_roles r WHERE r.rolname = session_user)",
    )
    .fetch_one(&maint)
    .await
    .expect("session probe");
    assert_eq!(session_user, "epigraph_maintenance");
    assert!(
        !bypassrls,
        "epigraph_maintenance must not hold BYPASSRLS: 067's header states the escape hatch is \
         ROLE MEMBERSHIP, and a bypassing role would make every assertion below vacuous"
    );

    let row = InstanceAdminRepository::grant(&maint, agent, Some(operator), Some("acceptance"))
        .await
        .expect(
            "the operator grant must succeed on epigraph_maintenance. instance_admins is FORCEd, \
             so this needs an INSERT policy whose disjunct epigraph_bypass() satisfies — the \
             REVOKE and the GRANT are not the control here, the policy set is.",
        );
    assert_eq!(row.agent_id, agent);
    assert_eq!(row.granted_by, Some(operator));
    assert!(row.revoked_at.is_none());

    assert!(
        InstanceAdminRepository::is_active(&pool, agent)
            .await
            .expect("is_active"),
        "the predicate must see the grant the operator just made"
    );

    // Re-granting is idempotent and goes through `ON CONFLICT DO UPDATE`, which
    // PostgreSQL checks against the SELECT-side policy as well as the UPDATE
    // one. A shape that had INSERT coverage only would pass the first grant and
    // fail here.
    InstanceAdminRepository::grant(&maint, agent, Some(operator), Some("re-grant"))
        .await
        .expect("ON CONFLICT DO UPDATE needs the UPDATE and SELECT sides, not just INSERT");

    // THE NEGATIVE. The same call on the app role must fail.
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "escalator").await;
    let denied = InstanceAdminRepository::grant(&app, other, Some(other), Some("self-grant")).await;
    assert!(
        denied.is_err(),
        "an app connection must not be able to write instance_admins. A token that could grant \
         itself the authority it is checked against is not an authority."
    );

    // CALIBRATION FOR THE NEGATIVE: the app pool is not simply broken. It can
    // reach the table, and the read policy narrows it to the caller's own row —
    // an unstamped app session is nobody, so it sees none of the live grants.
    let visible = InstanceAdminRepository::list(&app, true)
        .await
        .expect("the app role holds SELECT on instance_admins; a 42501 here is a migration bug");
    assert!(
        visible.is_empty(),
        "instance_admins_self_or_definer must narrow an unstamped app session to nothing; it \
         returned {visible:?}"
    );

    // THE UNSTAMPED ANSWER MUST BE `false`, NOT AN ERROR. `agent` holds a LIVE
    // grant at this point, and `app` is downgraded but NOT stamped — the exact
    // combination in which `epigraph_is_instance_admin` is three-valued at the
    // SQL level: `epigraph_principal_id()` is NULL, so the principal comparison
    // is NULL, `epigraph_bypass()` is false, and the roster `EXISTS` is true, so
    // the body is `true AND NULL AND true` = NULL unless 083 wraps it in
    // `COALESCE(…, false)`.
    //
    // This assertion is the one that distinguishes the two spellings. A bare
    // `bool` decode of a NULL is `sqlx::Error::ColumnDecode`, so without the
    // COALESCE this line panics on the `expect` rather than failing the compare
    // — and in production it is `ApiError::InternalError`, i.e. the 500 that
    // `middleware/instance_authz.rs`'s header says the function exists to turn
    // into a 403 with a reason. Three doc comments promise `false` here; this
    // is what holds them to it.
    assert!(
        !InstanceAdminRepository::is_active(&app, agent)
            .await
            .expect(
                "an unstamped app connection must get a DEFINITE false for a live admin, not a \
                 NULL that fails to decode into bool"
            ),
        "an unstamped app connection must not see a live grant as authorizing"
    );

    // Revocation is a stamp, and it flips the predicate back.
    assert!(
        InstanceAdminRepository::revoke(&maint, agent)
            .await
            .expect("revoke on the maintenance role"),
        "revoking a live grant must report that it changed a row — a FOR UPDATE policy with no \
         USING clause sees nothing to update and reports zero, silently"
    );
    assert!(
        !InstanceAdminRepository::is_active(&pool, agent)
            .await
            .expect("is_active after revoke"),
        "a revoked grant must not authorize"
    );
    let still_there: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM instance_admins WHERE agent_id = $1")
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("row survives revoke");
    assert_eq!(
        still_there, 1,
        "revocation must not delete the row: it is the record that the authority once existed"
    );

    // A second revoke is a no-op rather than an error, so re-running a completed
    // playbook step does not look like a failure.
    assert!(!InstanceAdminRepository::revoke(&maint, agent)
        .await
        .expect("second revoke"));
}

/// DELETE is default-denied on `instance_admins`, on the maintenance role too.
///
/// 083 grants DELETE to `epigraph_maintenance` and then installs no DELETE
/// policy, which under `FORCE` makes the GRANT inert. That is deliberate — the
/// write policies stop at INSERT and UPDATE rather than reaching for `FOR ALL`
/// — and it is the pair `rls_enforcement.rs::DELIBERATELY_UNCOVERED` records.
///
/// The observable is `rows_affected() == 0` and NOT an error: with no DELETE
/// policy the rows are simply not visible to the statement. Asserting the error
/// would have been wrong, and asserting only "the row is still there" would pass
/// against a `DELETE` that matched nothing for an unrelated reason — so both are
/// checked.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_is_denied_on_instance_admins_even_for_the_maintenance_role(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "undeletable").await;
    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    InstanceAdminRepository::grant(&maint, agent, None, None)
        .await
        .expect("grant");

    let deleted = sqlx::query("DELETE FROM instance_admins WHERE agent_id = $1")
        .bind(agent)
        .execute(&maint)
        .await
        .expect("DELETE is not an error, it is a no-op: there is no DELETE policy to deny it")
        .rows_affected();
    assert_eq!(deleted, 0, "no DELETE policy means no row is deletable");

    // The same statement on the superuser pool WOULD delete the row, which is
    // what makes the assertion above a measurement of the policy rather than of
    // a mis-typed WHERE clause.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM instance_admins WHERE agent_id = $1")
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(count, 1, "the row must survive the attempted DELETE");
}

/// Migration 088's UPDATE policies admit the maintenance role and nobody else.
///
/// # Why this needs its own test when `rls_enforcement.rs` already checks the
/// polcmd matrix
///
/// That test asserts a policy EXISTS for the pair; this asserts what it lets
/// through. Those are different claims, and the failure this one catches is the
/// one that would be invisible: a policy whose expression admits an app session
/// covers the pair perfectly well.
///
/// # BOTH directions, and the app-role half is the one that rots
///
/// A test that only showed the maintenance UPDATE succeeding would pass on a
/// `FOR ALL … USING (true)` policy. A test that only showed the app UPDATE
/// failing would pass on the state of the tree BEFORE 088, where no role could
/// update at all and `approve` was impossible. So both.
///
/// The app-role denial here arrives from the GRANT layer — migration 080 REVOKEs
/// UPDATE on both tables from `epigraph_app` — rather than from the policy, and
/// that is the honest description rather than a weaker one: two independent
/// controls say no, and if the REVOKE were ever loosened 088's policy is what
/// would still say it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_plan_state_machine_is_updatable_on_the_maintenance_role_and_not_on_the_app_role(
    pool: PgPool,
) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "state-machine").await;
    backdate_group(&pool, group).await;
    add_admin(&pool, group, "sm-co-1").await;
    add_admin(&pool, group, "sm-co-2").await;
    let plan = insert_plan(&pool, group, author)
        .await
        .expect("the guard admits a mature, plural target group");

    // ---- the app role. ----
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let denied = sqlx::query("UPDATE privatization_plans SET state = 'approved' WHERE id = $1")
        .bind(plan)
        .execute(&app)
        .await;
    assert!(
        denied.is_err(),
        "the app role must not be able to move a plan's state. Two controls say so — 080's \
         REVOKE and 088's bypass-only policy — and a success here means both are gone"
    );
    let denied_items =
        sqlx::query("UPDATE privatization_plan_items SET state = 'applied' WHERE plan_id = $1")
            .bind(plan)
            .execute(&app)
            .await;
    assert!(
        denied_items.is_err(),
        "the app role must not be able to mark an item applied; per-item state is the job \
         handler's and its authority is the re-validation, not a request"
    );

    // ---- the maintenance role. ----
    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let moved = sqlx::query("UPDATE privatization_plans SET state = 'applying' WHERE id = $1")
        .bind(plan)
        .execute(&maint)
        .await
        .expect("migration 088 must admit the maintenance role, or approve/apply cannot exist")
        .rows_affected();
    assert_eq!(
        moved, 1,
        "an UPDATE that matches zero rows on the maintenance role is what the tree looked like \
         BEFORE 088; this assertion is what tells the two apart"
    );

    // DELETE stays denied on both tables, on both roles. `FOR ALL` would have
    // covered it silently, and a plan is the record that a privatization was
    // attempted.
    for pool_under_test in [&app, &maint] {
        let deleted = sqlx::query("DELETE FROM privatization_plans WHERE id = $1")
            .bind(plan)
            .execute(pool_under_test)
            .await
            .map(|r| r.rows_affected())
            .unwrap_or(0);
        assert_eq!(deleted, 0, "no DELETE policy means no plan is deletable");
    }
    let survives: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM privatization_plans WHERE id = $1")
            .bind(plan)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(survives, 1);
}

/// Migration 081's plan guard refuses a target group an actor could manufacture.
///
/// "Group admin in the target group" prevented nothing on its own:
/// `POST /api/v1/groups` needs only `groups:write` and `create_with_admin`
/// inserts the creator as `role='admin'`, so a compliant target group was one
/// request away and the actor was its sole admin by construction. The two
/// conditions an actor cannot manufacture in one request are maturity and
/// plurality, and 081 puts both in the DATABASE — the HTTP check in
/// `middleware/instance_authz.rs` re-validates so a refusal is a 403 with a
/// reason rather than a 500 carrying a raw SQLSTATE, but it is not the control.
///
/// Run on the superuser pool ON PURPOSE. A trigger binds every role including a
/// `BYPASSRLS` one, so this is the one assertion in the file that is *stronger*
/// for being made as the owner: it shows the guard cannot be stepped around by
/// connecting differently.
#[sqlx::test(migrations = "../../migrations")]
async fn the_plan_guard_requires_a_mature_target_group_with_other_admins(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "planner").await;

    // A group created moments ago, with the author as its only admin: exactly
    // the shape `create_with_admin` produces.
    let young = insert_plan(&pool, group, author).await;
    assert!(
        young.is_err(),
        "a target group younger than 24h must be refused: it is one request away"
    );

    backdate_group(&pool, group).await;

    let alone = insert_plan(&pool, group, author).await;
    assert!(
        alone.is_err(),
        "maturity alone is not enough — a sole admin can still seize unilaterally"
    );

    add_admin(&pool, group, "co-admin-1").await;
    let one_other = insert_plan(&pool, group, author).await;
    assert!(
        one_other.is_err(),
        "one other admin is not two; the boundary is asserted, not just the extremes"
    );

    add_admin(&pool, group, "co-admin-2").await;
    insert_plan(&pool, group, author)
        .await
        .expect("a mature group with two other live admins is a legitimate target");

    // A revoked membership does not count. Without this the plurality condition
    // is satisfiable by adding two members and revoking them again.
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1 AND agent_id <> $2",
    )
    .bind(group)
    .bind(author)
    .execute(&pool)
    .await
    .expect("revoke the co-admins");
    let revoked = insert_plan(&pool, group, author).await;
    assert!(
        revoked.is_err(),
        "revoked admins must not count toward plurality"
    );
}

/// `privatization_audit` refuses UPDATE and DELETE by a trigger, so the refusal
/// binds the table owner too.
///
/// Asserted on the superuser pool deliberately, for the same reason as the guard
/// above and for the reason 082's header gives: RLS cannot express this. `ENABLE`
/// exempts the owner, `FORCE` does not defeat `BYPASSRLS`, and the connection
/// this test runs on holds both — so a policy-only answer would let the audit
/// trail be rewritten here and the test would be measuring nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn privatization_audit_is_append_only_against_a_bypassing_connection(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "auditor").await;
    backdate_group(&pool, group).await;
    add_admin(&pool, group, "audit-co-1").await;
    add_admin(&pool, group, "audit-co-2").await;
    let plan = insert_plan(&pool, group, author).await.expect("plan");

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO privatization_audit (plan_id, actor_agent_id, action) \
         VALUES ($1, $2, 'plan.create') RETURNING id",
    )
    .bind(plan)
    .bind(author)
    .fetch_one(&pool)
    .await
    .expect("an append must succeed, or the assertions below are vacuous");

    let updated = sqlx::query("UPDATE privatization_audit SET action = 'plan.abort' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
    assert!(
        updated.is_err(),
        "UPDATE on privatization_audit must raise, not silently affect zero rows"
    );

    let deleted = sqlx::query("DELETE FROM privatization_audit WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
    assert!(deleted.is_err(), "DELETE on privatization_audit must raise");

    let survivors: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM privatization_audit WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(survivors, 1, "the audit row must still be there, unchanged");
}

/// The same trigger, on `security_events` — the disjunct 077 deferred to 082.
///
/// `security_events` is the cross-cutting actor log a login, a token mint and a
/// privatization all land in. PR-17 shipped the default-deny half (no UPDATE and
/// no DELETE policy); 082 ships the half that also binds the owner.
#[sqlx::test(migrations = "../../migrations")]
async fn security_events_is_append_only_against_a_bypassing_connection(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "actor").await;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO security_events (event_type, agent_id, details) \
         VALUES ('test.append', $1, '{}'::jsonb) RETURNING id",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("an append must succeed, or the assertions below are vacuous");

    assert!(
        sqlx::query("UPDATE security_events SET event_type = 'test.rewritten' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .is_err(),
        "an actor must not be able to rewrite its own audit trail, owner or not"
    );
    assert!(
        sqlx::query("DELETE FROM security_events WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .is_err(),
        "nor erase it"
    );
}

/// **The largest read-surface change in PR-18a, measured in both directions.**
///
/// 083 recreates `security_events_read` with a fourth disjunct,
/// `epigraph_is_instance_admin(epigraph_principal_id())`. That is not "an admin
/// sees more rows of the same kind": the third disjunct is
/// `agent_id = epigraph_principal_id()`, which NULL never matches, so the
/// unattributed `agent_id IS NULL` rows that `security_events_append` admits
/// from pre-authentication paths were reachable only through a bypass before
/// this migration. The new arm adds a row CATEGORY, instance-wide.
///
/// A widened read policy whose positive and negative are reasoned about but
/// never executed is the vacuity shape this suite refuses elsewhere, so both
/// halves are executed here, and the negative is re-checked AFTER the grant so
/// the widening is shown to attach to the admin rather than to the app role.
#[sqlx::test(migrations = "../../migrations")]
async fn security_events_read_widens_to_the_whole_log_for_an_instance_admin_only(pool: PgPool) {
    let (admin, _) = fixture::seed_agent_with_group(&pool, "se-admin").await;
    let (bystander, _) = fixture::seed_agent_with_group(&pool, "se-bystander").await;

    // Seeded on the superuser pool so the fixtures exist independently of the
    // policy under test.
    let admins_own = insert_event(&pool, Some(admin), "test.admins-own").await;
    let bystanders_own = insert_event(&pool, Some(bystander), "test.bystanders-own").await;
    let unattributed = insert_event(&pool, None, "test.unattributed").await;

    // BEFORE THE GRANT. Nobody is an instance admin, so the fourth disjunct is
    // false for everyone and the policy is exactly what 077 shipped.
    let mut conn = stamped_app_conn(&pool, bystander).await;
    let seen = visible_events(&mut conn).await;
    assert!(
        seen.contains(&bystanders_own),
        "the third disjunct must still admit a principal's own rows"
    );
    assert!(
        !seen.contains(&admins_own),
        "a non-admin must not read another principal's actor log"
    );
    assert!(
        !seen.contains(&unattributed),
        "agent_id IS NULL never equals epigraph_principal_id(), so the unattributed rows must be \
         unreachable without the instance-admin arm — this is the assertion that makes the \
         widening below a CATEGORY change rather than a volume one"
    );
    drop(conn);

    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    InstanceAdminRepository::grant(&maint, admin, None, Some("read-surface"))
        .await
        .expect("grant");

    // AFTER THE GRANT, for the admin: the whole log, including the unattributed
    // rows.
    let mut conn = stamped_app_conn(&pool, admin).await;
    let seen = visible_events(&mut conn).await;
    assert!(
        seen.contains(&admins_own),
        "an admin still sees its own rows"
    );
    assert!(
        seen.contains(&bystanders_own),
        "the instance-admin arm must admit another principal's rows — this is the documented \
         widening, and a policy that failed to deliver it would leave 18b's forensic read broken"
    );
    assert!(
        seen.contains(&unattributed),
        "the instance-admin arm must admit the agent_id IS NULL rows"
    );
    drop(conn);

    // THE NEGATIVE, RE-CHECKED AFTER THE GRANT. The widening must attach to the
    // ADMIN, not to `epigraph_app`. Without this, a policy that had accidentally
    // been written `epigraph_is_instance_admin(agent_id)` — true for any row
    // belonging to any admin — would pass every assertion above.
    let mut conn = stamped_app_conn(&pool, bystander).await;
    let seen = visible_events(&mut conn).await;
    assert!(
        seen.contains(&bystanders_own),
        "the bystander still sees its own rows"
    );
    assert!(
        !seen.contains(&admins_own) && !seen.contains(&unattributed),
        "granting SOMEONE ELSE the authority must not widen what this principal reads"
    );
}

/// `privatization_audit_read` scopes `entity_id` rows to the plans whose target
/// group the caller administers, and to those only.
///
/// 082's header calls `entity_id` "a complete index of every private entity id
/// in the instance", so this row-level scoping is the whole of FINAL-PLAN
/// §6.5.2 point 3: "plan-level rows for every plan, entity ids only for plans
/// whose target group the caller administers".
///
/// # Why the shape of this test changed with migration 087
///
/// The arm reads
/// `epigraph_is_group_admin((SELECT p.target_group_id FROM privatization_plans p
/// WHERE p.id = privatization_audit.plan_id))`, and that scalar sub-select is
/// itself RLS-filtered. 083's own header records the consequence of shipping it
/// against a `privatization_plans` that had no SELECT policy: the sub-select
/// yielded NULL for every plan, `epigraph_is_group_admin(NULL)` was false, and
/// the ADMINISTERED direction was denied along with the unadministered one. An
/// earlier revision of this test asserted that blanket denial, because that was
/// the behaviour the policy set produced.
///
/// Migration 087 gives `privatization_plans` its SELECT policy, so the arm now
/// resolves and both directions are separately observable. The test is therefore
/// two-armed, which is what §6.5.2 point 3 actually specifies — and the second
/// arm is the one that matters, because a policy that simply admitted every
/// entity row to any instance admin would satisfy the first arm alone.
///
/// # Calibration
///
/// Three assertions carry it. The actor must be a live instance admin (or the
/// whole third disjunct is false and both arms pass vacuously); it must be a
/// live `role='admin'` of the ADMINISTERED plan's target group on the connection
/// under test (or arm one measures nothing); and it must NOT be an admin of the
/// other plan's target group (or arm two measures nothing).
#[sqlx::test(migrations = "../../migrations")]
async fn privatization_audit_entity_rows_follow_the_callers_group_adminship(pool: PgPool) {
    // The plan the actor administers.
    let (author, mine) = fixture::seed_agent_with_group(&pool, "pa-author").await;
    backdate_group(&pool, mine).await;
    add_admin(&pool, mine, "pa-co-1").await;
    add_admin(&pool, mine, "pa-co-2").await;
    let my_plan = insert_plan(&pool, mine, author).await.expect("plan");

    // A plan against a group the actor has nothing to do with. Its own author
    // is a different agent; 081's guard needs the same maturity and plurality.
    let (stranger, theirs) = fixture::seed_agent_with_group(&pool, "pa-stranger").await;
    backdate_group(&pool, theirs).await;
    add_admin(&pool, theirs, "pa-their-co-1").await;
    add_admin(&pool, theirs, "pa-their-co-2").await;
    let their_plan = insert_plan(&pool, theirs, stranger).await.expect("plan");

    let my_plan_level = insert_audit(&pool, my_plan, author, "plan.create", None).await;
    let my_entity_level =
        insert_audit(&pool, my_plan, author, "item.apply", Some(Uuid::new_v4())).await;
    let their_plan_level = insert_audit(&pool, their_plan, stranger, "plan.create", None).await;
    let their_entity_level = insert_audit(
        &pool,
        their_plan,
        stranger,
        "item.apply",
        Some(Uuid::new_v4()),
    )
    .await;

    // BEFORE THE GRANT. Not an instance admin: the whole third disjunct is
    // false, so no row is readable — not even a plan-level one.
    let mut conn = stamped_app_conn(&pool, author).await;
    let seen = visible_audit(&mut conn).await;
    assert!(
        seen.is_empty(),
        "a principal that is not an instance admin must read no privatization_audit rows at \
         all, not even plan-level ones; it saw {seen:?}"
    );
    drop(conn);

    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    InstanceAdminRepository::grant(&maint, author, None, Some("audit-read"))
        .await
        .expect("grant");

    let mut conn = stamped_app_conn(&pool, author).await;

    // CALIBRATION, both directions, on THIS connection.
    let administers_mine: bool = sqlx::query_scalar("SELECT public.epigraph_is_group_admin($1)")
        .bind(mine)
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_is_group_admin(mine)");
    assert!(
        administers_mine,
        "the actor must be a live admin of its own plan's target group, or the first arm \
         measures nothing"
    );
    let administers_theirs: bool = sqlx::query_scalar("SELECT public.epigraph_is_group_admin($1)")
        .bind(theirs)
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_is_group_admin(theirs)");
    assert!(
        !administers_theirs,
        "the actor must NOT administer the other plan's target group, or the second arm is a \
         restatement of the first"
    );

    let seen = visible_audit(&mut conn).await;

    // PLAN-LEVEL: every plan, including one the actor does not administer.
    assert!(
        seen.contains(&my_plan_level) && seen.contains(&their_plan_level),
        "an instance admin must see plan-level rows (entity_id IS NULL) for EVERY plan; an \
         auditor needs the instance-wide timeline (FINAL-PLAN §6.5.8)"
    );

    // ARM ONE — the administered plan's entity ids are readable. This is what
    // migration 087 makes reachable.
    assert!(
        seen.contains(&my_entity_level),
        "an instance admin who is a live admin of a plan's target group must see that plan's \
         entity-level rows; that is FINAL-PLAN §6.5.2 point 3's 'entity ids only for plans whose \
         target group the caller administers', and it is reachable because migration 087 gives \
         privatization_plans the SELECT policy the arm's sub-select needs"
    );

    // ARM TWO — the unadministered plan's entity ids are NOT. This is the
    // control, and it is the assertion that fails silently: a policy admitting
    // every entity row to any instance admin passes arm one unchanged.
    assert!(
        !seen.contains(&their_entity_level),
        "entity-level rows for a plan whose target group the caller does NOT administer must \
         stay denied. instance:admin alone is explicitly not sufficient for entity ids"
    );
}

// ===========================================================================
// Fixtures local to this file
// ===========================================================================

/// A single connection authenticated as `epigraph_app` and STAMPED with
/// `epigraph.principal_id = principal`.
///
/// [`fixture::downgraded_pool`] changes `session_user` and confers no
/// `BYPASSRLS`, but it does NOT stamp the principal GUC — an unstamped session
/// is nobody, and every self-or-admin policy arm would be false for a reason
/// that has nothing to do with the arm under test. Both halves are needed to
/// observe a read policy at all, so the calibration below asserts both took.
async fn stamped_app_conn(
    pool: &PgPool,
    principal: Uuid,
) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let app = fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut conn = app.acquire().await.expect("acquire an app connection");
    sqlx::query("SELECT set_config('epigraph.principal_id', $1::text, false)")
        .bind(principal)
        .execute(&mut *conn)
        .await
        .expect("stamp epigraph.principal_id");

    let (session_user, bypassrls, observed): (String, bool, Option<Uuid>) = sqlx::query_as(
        "SELECT session_user::text, \
                (SELECT r.rolbypassrls FROM pg_roles r WHERE r.rolname = session_user), \
                public.epigraph_principal_id()",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("session probe");
    assert_eq!(
        session_user, "epigraph_app",
        "the connection must really be downgraded, or FORCE is not in play"
    );
    assert!(
        !bypassrls,
        "epigraph_app must not hold BYPASSRLS, or every policy assertion is vacuous"
    );
    assert_eq!(
        observed,
        Some(principal),
        "the principal stamp must have taken, or every self-or-admin arm is false for the wrong \
         reason"
    );
    conn
}

/// Append a `security_events` row on the superuser pool. Returns its id.
async fn insert_event(pool: &PgPool, agent: Option<Uuid>, event_type: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO security_events (event_type, agent_id, details) \
         VALUES ($1, $2, '{}'::jsonb) RETURNING id",
    )
    .bind(event_type)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed security_events row")
}

/// Every `security_events` id visible to `conn` under its own session.
async fn visible_events(conn: &mut sqlx::PgConnection) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT id FROM security_events")
        .fetch_all(conn)
        .await
        .expect("the app role holds SELECT on security_events; a 42501 here is a migration bug")
}

/// Append a `privatization_audit` row on the superuser pool. Returns its id.
async fn insert_audit(
    pool: &PgPool,
    plan: Uuid,
    actor: Uuid,
    action: &str,
    entity: Option<Uuid>,
) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO privatization_audit (plan_id, actor_agent_id, action, kind, entity_id) \
         VALUES ($1, $2, $3, CASE WHEN $4::uuid IS NULL THEN NULL ELSE 'claim' END, $4) \
         RETURNING id",
    )
    .bind(plan)
    .bind(actor)
    .bind(action)
    .bind(entity)
    .fetch_one(pool)
    .await
    .expect("seed privatization_audit row")
}

/// Every `privatization_audit` id visible to `conn` under its own session.
async fn visible_audit(conn: &mut sqlx::PgConnection) -> Vec<i64> {
    sqlx::query_scalar("SELECT id FROM privatization_audit")
        .fetch_all(conn)
        .await
        .expect("the app role holds SELECT on privatization_audit; a 42501 here is a migration bug")
}

/// Attempt the plan INSERT 081's guard fires on. Returns the plan id or the
/// database error, so a caller can assert either direction.
async fn insert_plan(pool: &PgPool, group: Uuid, author: Uuid) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO privatization_plans (mode, target_group_id, selector, created_by) \
         VALUES ('restrict', $1, '{}'::jsonb, $2) RETURNING id",
    )
    .bind(group)
    .bind(author)
    .fetch_one(pool)
    .await
}

/// Age a group past 081's 24-hour maturity condition.
async fn backdate_group(pool: &PgPool, group: Uuid) {
    sqlx::query("UPDATE groups SET created_at = now() - interval '48 hours' WHERE id = $1")
        .bind(group)
        .execute(pool)
        .await
        .expect("backdate group");
}

/// Add a second live `admin` membership to `group`.
async fn add_admin(pool: &PgPool, group: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed co-admin membership");
    agent
}

// ===========================================================================
// Acceptance clause 1, the negative direction: `not_visible_to_actor` is a
// COUNT WITH NO IDS.
//
// This is the half of the clause that fails silently. "The preview reported 7
// items" is satisfied by a preview that also leaked all 7 ids and their
// content; only an assertion on the ABSENCE of the id can tell the two apart.
//
// It runs on a STAMPED, DOWNGRADED connection rather than on the `#[sqlx::test]`
// pool. `DATABASE_URL` is `epigraph` — `rolsuper`, `rolbypassrls` — so on the
// default pool every row is visible to every actor, and the negative assertion
// below would pass against a rendering pass that had no predicate at all. That
// is the same trap this file's module doc records for the write side.
// ===========================================================================

/// The rendering pass returns ids and content ONLY for what the actor can read,
/// while the selection pass counts everything.
///
/// The two-pass split is the sec-F7 closure: selection must be unfiltered to
/// produce a correct plan, and rendering must be filtered or the preview is an
/// exfiltration channel. This asserts both halves at once, which is the only
/// way to tell the fix from either failure mode — a filtered selection (wrong
/// plan) and an unfiltered rendering (the oracle) each satisfy one assertion
/// and fail the other.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rendering_pass_yields_no_id_and_no_content_for_what_the_actor_cannot_read(
    pool: PgPool,
) {
    let (actor, _actor_group) = fixture::seed_agent_with_group(&pool, "render-actor").await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "render-stranger").await;

    const SECRET: &str = "the stranger's private content";
    let readable = fixture::seed_public_claim(&pool, actor, "public and readable").await;
    let hidden = fixture::seed_group_claim(&pool, stranger, stranger_group, SECRET).await;
    let candidates = vec![readable, hidden];

    // SELECTION: unfiltered, and it must see BOTH. If this half ever returns 1,
    // the plan is wrong rather than leaky, and the assertion below stops
    // measuring anything.
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let mut maintenance = pool.acquire().await.expect("acquire");
    let counted = PrivatizationRepository::count_selected(&mut maintenance, &bypass, &candidates)
        .await
        .expect("unfiltered count");
    assert_eq!(
        counted, 2,
        "selection runs unfiltered and must count the stranger's claim too — a filtered \
         selection silently omits exactly the rows privatization exists to find"
    );
    drop(maintenance);

    // RENDERING: the actor's own authority, on a connection that really is
    // subject to the policy.
    let mut conn = fully_stamped_app_conn(&pool, actor).await;
    let actor_viewer = epigraph_db::visibility::Viewer::resolve(&pool, actor)
        .await
        .expect("resolve the actor");
    let rendered = PrivatizationRepository::visible_previews(&mut conn, &actor_viewer, &candidates)
        .await
        .expect("render");

    let rendered_ids: Vec<Uuid> = rendered.iter().map(|p| p.claim_id).collect();
    assert!(
        rendered_ids.contains(&readable),
        "POSITIVE CONTROL: the actor must still get the claim it CAN read. Without this, an \
         implementation that renders nothing at all passes every assertion below"
    );
    assert!(
        !rendered_ids.contains(&hidden),
        "the id of a claim the actor cannot read must not appear. An id is itself the \
         disclosure: it names an entity in another tenant's private region"
    );
    for preview in &rendered {
        assert!(
            !preview.preview.contains(SECRET),
            "no rendered preview may carry content the actor cannot read"
        );
    }

    // `not_visible_to_actor` is the DIFFERENCE, and it is reported as a number.
    let not_visible = counted - i64::try_from(rendered.len()).expect("small");
    assert_eq!(
        not_visible, 1,
        "the preview reports what it withheld as a count, so the operator learns the plan is \
         larger than what they can inspect without learning what is in it"
    );

    // CALIBRATION: the stranger CAN read its own claim on the same code path,
    // so the denial above is attributable to the actor's authority and not to a
    // rendering pass that is simply broken.
    drop(conn);
    let mut stranger_conn = fully_stamped_app_conn(&pool, stranger).await;
    let stranger_viewer = epigraph_db::visibility::Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve the stranger");
    let stranger_sees = PrivatizationRepository::visible_previews(
        &mut stranger_conn,
        &stranger_viewer,
        &candidates,
    )
    .await
    .expect("render for the stranger");
    assert!(
        stranger_sees.iter().any(|p| p.claim_id == hidden),
        "the owner of the private claim must read it through the very same function"
    );
}

/// A downgraded `epigraph_app` connection stamped with BOTH session GUCs.
///
/// # Why [`stamped_app_conn`] is not enough here
///
/// That helper stamps `epigraph.principal_id` only, which is all the
/// `instance_admins` and `privatization_audit` policies read. `claims_tenancy`
/// is a different shape: its last disjunct is
/// `owner_group_id = ANY(epigraph_session_groups())`, and
/// `epigraph_session_groups()` reads the **`epigraph.group_ids`** GUC — a
/// second stamp that migration 067 keeps deliberately separate from the
/// principal.
///
/// Measured: with `principal_id` alone, a principal cannot read its **own**
/// group-private claim, because the group array is empty and only the
/// `visibility = 'public'` disjunct can match. A negative assertion written on
/// such a connection passes for a reason that has nothing to do with the code
/// under test, and its positive control fails — which is how this was caught.
///
/// Stamping both is also what makes the two halves of plan §4.5's qual/GUC
/// coherence agree on this connection: the `Viewer` supplies `$V` to the
/// spliced predicate, and the identical group set reaches the RLS policy
/// through the GUC. A row filtered by one is filtered by the other, so a test
/// on this connection cannot pass because RLS silently compensated for a
/// missing application predicate — or the reverse.
async fn fully_stamped_app_conn(
    pool: &PgPool,
    principal: Uuid,
) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let groups: Vec<Uuid> = sqlx::query_scalar(
        "SELECT group_id FROM group_memberships WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(principal)
    .fetch_all(pool)
    .await
    .expect("read live memberships");

    let app = fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut conn = app.acquire().await.expect("acquire an app connection");
    sqlx::query("SELECT set_config('epigraph.principal_id', $1::text, false)")
        .bind(principal)
        .execute(&mut *conn)
        .await
        .expect("stamp epigraph.principal_id");
    let joined = groups
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query("SELECT set_config('epigraph.group_ids', $1, false)")
        .bind(&joined)
        .execute(&mut *conn)
        .await
        .expect("stamp epigraph.group_ids");

    // CALIBRATION. Both stamps took, and the connection really is downgraded —
    // without all three of these the assertions built on this connection are
    // vacuous in three different ways.
    let (session_user, bypassrls, observed, observed_groups): (
        String,
        bool,
        Option<Uuid>,
        Vec<Uuid>,
    ) = sqlx::query_as(
        "SELECT session_user::text, \
                (SELECT r.rolbypassrls FROM pg_roles r WHERE r.rolname = session_user), \
                public.epigraph_principal_id(), \
                public.epigraph_session_groups()",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("session probe");
    assert_eq!(
        session_user, "epigraph_app",
        "the connection must really be downgraded, or FORCE is not in play"
    );
    assert!(
        !bypassrls,
        "epigraph_app must not hold BYPASSRLS, or every policy assertion is vacuous"
    );
    assert_eq!(
        observed,
        Some(principal),
        "the principal stamp must have taken"
    );
    assert_eq!(
        observed_groups.len(),
        groups.len(),
        "the group stamp must have taken, or claims_tenancy sees an empty group array and the \
         principal cannot read its own group-private rows"
    );
    conn
}

/// Both rendering functions REFUSE a bypass viewer, at runtime.
///
/// # Why an assertion on a `debug_assert!` would have been worthless
///
/// The root `Cargo.toml` declares no `[profile.release]`, so `release` takes
/// cargo's default `debug-assertions = false` and a `debug_assert!` guard is
/// simply not in the shipped binary. A test run under `cargo test` compiles
/// with debug assertions ON, so a test can only ever observe the guard that is
/// absent from production — which is why the guard on this side of the split is
/// an `if … return Err(…)` and this test asserts an `Err`, not a panic.
///
/// The selection side keeps its `debug_assert!`s deliberately: handing them the
/// wrong viewer produces an under-selected plan, which is wrong and visible,
/// where handing the rendering side a bypass viewer emits ids and content for
/// entities the actor cannot read, which is neither.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rendering_pass_refuses_a_bypass_viewer_rather_than_asserting(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "render-refusal").await;
    let claim = fixture::seed_public_claim(&pool, agent, "a claim").await;
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");

    let previews = PrivatizationRepository::visible_previews(&mut conn, &bypass, &[claim]).await;
    assert!(
        matches!(
            previews,
            Err(SelectionError::Refused(
                SelectionRefusal::BypassViewerInRenderingPass
            ))
        ),
        "rendering under a bypass viewer must be refused, not merely asserted against: \
         got {previews:?}"
    );

    let edges =
        PrivatizationRepository::visible_boundary_edges(&mut conn, &bypass, &[claim], 10).await;
    assert!(
        matches!(
            edges,
            Err(SelectionError::Refused(
                SelectionRefusal::BypassViewerInRenderingPass
            ))
        ),
        "the boundary-edge SAMPLE carries ids and must be refused the same way: got {edges:?}"
    );

    // CALIBRATION. The same two calls SUCCEED under the actor's own viewer, so
    // the refusals above are attributable to the viewer shape and not to a code
    // path that errors for every input.
    let actor = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("resolve the actor");
    PrivatizationRepository::visible_previews(&mut conn, &actor, &[claim])
        .await
        .expect("a scoped viewer must be accepted");
    PrivatizationRepository::visible_boundary_edges(&mut conn, &actor, &[claim], 10)
        .await
        .expect("a scoped viewer must be accepted");
}
