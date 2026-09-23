//! Migration 087: who can persist a privatization plan, and who can read one
//! back.
//!
//! # The vacuity problem, restated for this file
//!
//! `DATABASE_URL` is `epigraph`: `rolsuper`, `rolbypassrls`, and the owner of
//! every table here. `BYPASSRLS` defeats `FORCE ROW LEVEL SECURITY` outright, so
//! **every assertion in this file that is about a POLICY runs on
//! `viewer_fixture::downgraded_pool`**, whose `after_connect` issues
//! `SET SESSION AUTHORIZATION` — that changes `session_user`, which is the value
//! `epigraph_bypass()` reads, and confers no `BYPASSRLS`.
//!
//! The plan tables are the one place in this subsystem where the policy is the
//! ONLY control. `privatization_plans` and `privatization_plan_items` have no
//! `visibility` column and no `owner_group_id`, so there is no in-query
//! predicate to splice and no second, independent filter. A read of them on a
//! superuser pool observes nothing at all.
//!
//! # What each arm is for
//!
//! Migration 087's read policy is `epigraph_bypass() OR
//! epigraph_definer_bypass() OR (epigraph_is_instance_admin(principal) AND
//! epigraph_is_group_admin(target_group))`. A test that only asserted the
//! positive would pass against a policy missing either conjunct, so each
//! negative below removes exactly one of them and keeps the rest:
//!
//! * an instance admin who does NOT administer the target group — the sec-F7b
//!   control, and the exact shape FINAL-PLAN §6.5.2 point 2 records as the
//!   previous revision's cross-tenant read;
//! * a group admin of the target group who is NOT an instance admin;
//! * the plan's own author, before the instance grant.

mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

use epigraph_db::repos::instance_admin::InstanceAdminRepository;
use epigraph_db::repos::privatization::{
    ClosureDirection, ClosureRequest, NewPlan, PrivatizationRepository, SelectedClaim,
    SelectionError, SelectionRefusal, UnfilteredSelection, MAX_NODE_CAP, MAX_TRAVERSAL_DEPTH,
};
use epigraph_db::visibility::Viewer;

const NO_TIMEOUT_CONCERN: std::time::Duration = std::time::Duration::from_secs(30);

// ===========================================================================
// Persist, then read back.
// ===========================================================================

/// The whole 18b round trip on real connections: select on maintenance, freeze
/// on maintenance, read back on the actor's own stamped app connection.
///
/// This is the assertion migration 087 exists for. Before it, `FORCE` with an
/// empty policy set denied the INSERT to every role including
/// `epigraph_maintenance` (`rolbypassrls = f`), so a plan could not be persisted
/// at all — which is why FINAL-PLAN §6.5.1's "selection is a persisted plan,
/// never a stateless request" could not be satisfied and no preview route could
/// exist.
#[sqlx::test(migrations = "../../migrations")]
async fn a_plan_persists_on_maintenance_and_reads_back_for_the_target_groups_admin(pool: PgPool) {
    let world = World::seed(&pool).await;

    let frozen = world.freeze_a_plan(&pool).await;

    let mut conn = stamped_admin_conn(&pool, world.actor).await;
    let plan = PrivatizationRepository::load_plan_conn(&mut conn, frozen.plan_id)
        .await
        .expect("load_plan")
        .expect("the target group's own instance admin must be able to read the plan it created");
    assert_eq!(
        plan.item_count, 2,
        "both seeded claims are in the frozen set"
    );
    assert_eq!(plan.state, "previewed");
    assert_eq!(
        plan.plan_digest.as_deref(),
        Some(frozen.digest.as_slice()),
        "the stored digest must be the one the selection computed; an apply echoes it"
    );

    let items = PrivatizationRepository::load_plan_items_conn(&mut conn, frozen.plan_id, 0, 100)
        .await
        .expect("load_plan_items");
    assert_eq!(items.len(), 2, "the frozen item set reads back complete");
    assert!(
        items
            .iter()
            .all(|i| i.kind == "claim" && i.state == "pending"),
        "items are frozen as pending claims: {items:?}"
    );
    assert!(
        items.iter().any(|i| i.depth == 0),
        "the seed must be recorded at depth 0"
    );

    let listed = PrivatizationRepository::list_plans_conn(&mut conn, None, None, 50)
        .await
        .expect("list_plans");
    assert!(
        listed.iter().any(|p| p.id == frozen.plan_id),
        "the plan appears in the caller's own list"
    );
}

/// **The sec-F7b control.** An instance admin who does not administer the target
/// group reads neither the plan nor a single one of its items.
///
/// FINAL-PLAN §6.5.2 point 2: the previous revision of this design required
/// `instance:admin` plus group-admin-in-target to CREATE a plan and only
/// `instance:admin` to READ one, "so any instance admin could read any other
/// admin's preview, its content sample, and the complete entity-id list of their
/// private region". The narrowing is in the policy rather than only in a
/// handler, so a route that forgot its check returns nothing rather than
/// somebody else's plan.
///
/// The calibration matters more here than the assertion: the outsider is a LIVE
/// instance admin, so the first conjunct of 087's third disjunct is true and the
/// denial is attributable to the group-adminship conjunct alone.
#[sqlx::test(migrations = "../../migrations")]
async fn an_instance_admin_who_does_not_administer_the_target_group_reads_no_plan(pool: PgPool) {
    let world = World::seed(&pool).await;
    let frozen = world.freeze_a_plan(&pool).await;

    // A second instance admin, with no membership of the target group at all.
    let (outsider, _own_group) = fixture::seed_agent_with_group(&pool, "pp-outsider").await;
    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    InstanceAdminRepository::grant(&maint, outsider, None, Some("outsider"))
        .await
        .expect("grant the outsider instance admin");

    let mut conn = stamped_admin_conn(&pool, outsider).await;

    // CALIBRATION, both halves.
    let is_instance_admin: bool =
        sqlx::query_scalar("SELECT public.epigraph_is_instance_admin($1)")
            .bind(outsider)
            .fetch_one(&mut *conn)
            .await
            .expect("epigraph_is_instance_admin");
    assert!(
        is_instance_admin,
        "the outsider must be a LIVE instance admin, or this test measures the instance-admin \
         conjunct instead of the group-admin one"
    );
    let administers: bool = sqlx::query_scalar("SELECT public.epigraph_is_group_admin($1)")
        .bind(world.target_group)
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_is_group_admin");
    assert!(
        !administers,
        "the outsider must not administer the target group, or the denial below is expected for \
         the wrong reason"
    );

    assert!(
        PrivatizationRepository::load_plan_conn(&mut conn, frozen.plan_id)
            .await
            .expect("load_plan")
            .is_none(),
        "instance:admin alone must not reach another admin's plan"
    );
    assert!(
        PrivatizationRepository::load_plan_items_conn(&mut conn, frozen.plan_id, 0, 100)
            .await
            .expect("load_plan_items")
            .is_empty(),
        "instance:admin alone must not reach the frozen item set — it is a complete index of \
         every entity the plan would privatize"
    );
    assert!(
        PrivatizationRepository::list_plans_conn(&mut conn, None, None, 50)
            .await
            .expect("list_plans")
            .is_empty(),
        "the list endpoint is narrowed by the same policy, not by a handler-side filter"
    );
}

/// **`list_plans_conn` has TWO independent filters, and this arm removes the
/// policy to show the other one still binds.**
///
/// Its two sibling reads each carry a second control — their callers re-check
/// FINAL-PLAN §6.6 against the plan's own `target_group_id` on a maintenance
/// connection — and an earlier revision of `list_plans_conn` carried none,
/// delegating everything to migration 087's SELECT policy. That is the one
/// surface where a single event (an unstamped connection, a future `NO FORCE`, a
/// dropped policy, a fixture reusing a privileged role) would have turned the
/// endpoint into FINAL-PLAN §6.5.2's cross-tenant read.
///
/// So the §6.6 conjunction is spliced into the statement as well, and this test
/// runs on the connection where the POLICY does nothing: the `#[sqlx::test]`
/// pool is `rolsuper` and `rolbypassrls`, so `epigraph_bypass()` is true and
/// 087's first disjunct admits every row. The calibration is the whole test —
/// `load_plan_conn`, which has no spliced predicate, MUST return the plan on
/// this same connection. If it did not, the emptiness below would be the policy
/// denying rather than the predicate, and the assertion would measure nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_plan_list_is_narrowed_by_its_own_predicate_and_not_only_by_the_policy(pool: PgPool) {
    let world = World::seed(&pool).await;
    let frozen = world.freeze_a_plan(&pool).await;

    let mut conn = pool.acquire().await.expect("acquire the test pool");

    // CALIBRATION: on this connection the policy admits everything.
    assert!(
        PrivatizationRepository::load_plan_conn(&mut conn, frozen.plan_id)
            .await
            .expect("load_plan_conn")
            .is_some(),
        "CALIBRATION: 087's policy must be admitting rows on this connection, or the emptiness \
         below is the policy's doing and this test measures nothing"
    );

    assert!(
        PrivatizationRepository::list_plans_conn(&mut conn, None, None, 50)
            .await
            .expect("list_plans_conn")
            .is_empty(),
        "the list statement's own §6.6 predicate must refuse a connection with no stamped \
         principal, independently of whether the policy is filtering"
    );
}

/// A group admin of the target group who is NOT an instance admin reads nothing
/// either.
///
/// The other half of 087's conjunction. Without this arm a policy written
/// `epigraph_is_group_admin(target_group_id)` alone would pass every other test
/// in this file.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_admin_who_is_not_an_instance_admin_reads_no_plan(pool: PgPool) {
    let world = World::seed(&pool).await;
    let frozen = world.freeze_a_plan(&pool).await;

    let mut conn = stamped_admin_conn(&pool, world.co_admin).await;
    let administers: bool = sqlx::query_scalar("SELECT public.epigraph_is_group_admin($1)")
        .bind(world.target_group)
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_is_group_admin");
    assert!(
        administers,
        "the co-admin must really administer the target group, or this arm measures nothing"
    );

    assert!(
        PrivatizationRepository::load_plan_conn(&mut conn, frozen.plan_id)
            .await
            .expect("load_plan")
            .is_none(),
        "administering the target group is necessary and not sufficient; the instance grant is \
         the other conjunct"
    );
}

/// The app role cannot write a plan, by two independent controls.
///
/// 080 REVOKEs INSERT from `epigraph_app` and 087's INSERT policy admits
/// `epigraph_bypass()` only. Either alone would deny it; the assertion is that
/// the write does not succeed, and the calibration is that the SAME statement
/// succeeds on the maintenance role, so the denial is not a malformed INSERT.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_persist_a_plan_and_the_maintenance_role_can(pool: PgPool) {
    let world = World::seed(&pool).await;
    let selector = serde_json::json!({ "seeds": { "ids": { "claims": [] } } });

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let mut app_conn = app.acquire().await.expect("acquire app connection");
    let denied = PrivatizationRepository::create_previewed_plan(
        &mut app_conn,
        NewPlan {
            mode: "restrict",
            target_group_id: world.target_group,
            selector: &selector,
            on_conflict: "abort",
            pad_to: 256,
            created_by: world.actor,
            plan_digest: &[0u8; 32],
            item_count: 0,
            authors_losing_count: 0,
        },
    )
    .await;
    assert!(
        denied.is_err(),
        "the app role must not be able to persist a privatization plan"
    );

    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let mut maint_conn = maint
        .acquire()
        .await
        .expect("acquire maintenance connection");
    PrivatizationRepository::create_previewed_plan(
        &mut maint_conn,
        NewPlan {
            mode: "restrict",
            target_group_id: world.target_group,
            selector: &selector,
            on_conflict: "abort",
            pad_to: 256,
            created_by: world.actor,
            plan_digest: &[0u8; 32],
            item_count: 0,
            authors_losing_count: 0,
        },
    )
    .await
    .expect(
        "CALIBRATION: the same statement must succeed on epigraph_maintenance. If it does not, \
         the denial above is a malformed INSERT rather than a policy",
    );
}

// ===========================================================================
// The rendering pass, on a downgraded connection.
// ===========================================================================

/// `visible_boundary_edges` filters on a connection where the RLS policy is
/// live, not only on the spliced predicate.
///
/// Its existing coverage in `privatization_boundary.rs` runs on the
/// `#[sqlx::test]` pool, which connects as `epigraph` — `rolsuper`,
/// `rolbypassrls`, table owner — so those arms observe the in-query `$V`
/// predicate and the `edges_tenancy` policy is not part of what they measure.
/// This arm adds the missing half by running the same call on a downgraded,
/// fully stamped `epigraph_app` connection, where both are in play.
///
/// The assertion is on the ABSENCE of an id, which is the direction that fails
/// silently, and it is calibrated by a positive control on the same connection.
#[sqlx::test(migrations = "../../migrations")]
async fn the_boundary_edge_sample_filters_under_the_policy_as_well_as_the_predicate(pool: PgPool) {
    let (author, group_g) = fixture::seed_agent_with_group(&pool, "bp-g").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "bp-stranger").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let world = fixture::world_group(&pool).await;
    let inside = fixture::seed_group_claim(&pool, author, group_g, "inside G").await;
    let outside_public = fixture::seed_public_claim(&pool, author, "outside, public").await;
    let outside_private = fixture::seed_group_claim(&pool, author, group_g, "outside, G").await;

    // One boundary edge the stranger may read, one it may not.
    let public_edge =
        fixture::seed_edge_owned_by(&pool, inside, outside_public, "public", world).await;
    let private_edge =
        fixture::seed_edge_owned_by(&pool, inside, outside_private, "group", group_g).await;

    let selected = vec![inside];

    // POSITIVE CONTROL — a member of G sees both boundary edges on a stamped,
    // downgraded connection. Without it, the negative below is satisfied by a
    // query that returns nothing at all.
    let member_viewer = Viewer::resolve(&pool, author)
        .await
        .expect("resolve author");
    let mut member_conn = fully_stamped_app_conn(&pool, author).await;
    let seen = PrivatizationRepository::visible_boundary_edges(
        &mut member_conn,
        &member_viewer,
        &selected,
        10,
    )
    .await
    .expect("visible_boundary_edges as a member");
    assert!(
        seen.contains(&public_edge) && seen.contains(&private_edge),
        "CALIBRATION: a member of the owning group must see both boundary edges under the policy \
         AND the predicate; it saw {seen:?}"
    );

    // THE ASSERTION. A stranger sees the public boundary edge and NOT the
    // group-private one — no id, no substitute, no placeholder.
    let stranger_viewer = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");
    let mut stranger_conn = fully_stamped_app_conn(&pool, stranger).await;
    let seen = PrivatizationRepository::visible_boundary_edges(
        &mut stranger_conn,
        &stranger_viewer,
        &selected,
        10,
    )
    .await
    .expect("visible_boundary_edges as a stranger");
    assert!(
        !seen.contains(&private_edge),
        "the boundary-edge SAMPLE is the rendering pass and must name only edges the actor's own \
         authority admits; it saw {seen:?}"
    );
    assert!(
        seen.contains(&public_edge),
        "CALIBRATION: the stranger must still see the public boundary edge, or the assertion \
         above is satisfied by a query that returns nothing"
    );
}

// ===========================================================================
// FINAL-PLAN §3.1's two request ceilings.
// ===========================================================================

/// `node_cap` and `max_depth` above the system maxima are REFUSED, not clamped.
///
/// FINAL-PLAN §3.1's words are "a 400, not a truncation". The two refusals are
/// distinct variants from [`SelectionRefusal::NodeCapExceeded`], which answers a
/// different question — a selection overflowing the cap the caller asked for —
/// and the calibration below is that a request AT each ceiling is accepted, so
/// the refusal is a ceiling rather than a blanket denial.
#[sqlx::test(migrations = "../../migrations")]
async fn a_request_above_either_system_ceiling_is_refused_rather_than_clamped(pool: PgPool) {
    let (scoped, bypass) = fixture::bypass(&pool).await;
    let (author, _group) = fixture::seed_agent_with_group(&pool, "ceil").await;
    let seed = fixture::seed_public_claim(&pool, author, "ceiling seed").await;
    let seeds = vec![seed];
    let edge_types = vec!["derived_from".to_string()];
    let mut conn = scoped.inner().acquire().await.expect("acquire");

    let base = ClosureRequest {
        seeds: &seeds,
        edge_types: &edge_types,
        direction: ClosureDirection::Both,
        max_depth: MAX_TRAVERSAL_DEPTH,
        node_cap: MAX_NODE_CAP,
    };

    // CALIBRATION: exactly at both ceilings is accepted.
    PrivatizationRepository::select_closure(&mut conn, &bypass, base)
        .await
        .expect(
            "a request AT both ceilings must be accepted, or the refusals below are a \
                 blanket denial rather than a ceiling",
        );

    let too_deep = ClosureRequest {
        max_depth: MAX_TRAVERSAL_DEPTH + 1,
        ..base
    };
    match PrivatizationRepository::select_closure(&mut conn, &bypass, too_deep).await {
        Err(SelectionError::Refused(SelectionRefusal::DepthAboveSystemMaximum {
            requested,
            maximum,
        })) => {
            assert_eq!(requested, MAX_TRAVERSAL_DEPTH + 1);
            assert_eq!(maximum, MAX_TRAVERSAL_DEPTH);
        }
        other => panic!("max_depth above the ceiling must be refused, got {other:?}"),
    }

    let too_wide = ClosureRequest {
        node_cap: MAX_NODE_CAP + 1,
        ..base
    };
    match PrivatizationRepository::select_closure(&mut conn, &bypass, too_wide).await {
        Err(SelectionError::Refused(SelectionRefusal::NodeCapAboveSystemMaximum {
            requested,
            maximum,
        })) => {
            assert_eq!(requested, MAX_NODE_CAP + 1);
            assert_eq!(maximum, MAX_NODE_CAP);
        }
        other => panic!("node_cap above the ceiling must be refused, got {other:?}"),
    }
}

// ===========================================================================
// The two-pass split, at the type level.
// ===========================================================================

/// The rendering exits of [`UnfilteredSelection`] refuse the bypass viewer that
/// produced it.
///
/// The type is what stops a handler serialising selection-pass ids, but a type
/// cannot stop a handler passing the WRONG viewer to a rendering exit, so both
/// exits refuse a bypass viewer at RUNTIME — `debug_assertions` is off in a
/// release profile and the fail-open direction here is a disclosure.
///
/// `visible_count` is included because it is the production half of
/// `not_visible_to_actor`: called with a bypass viewer it would equal
/// `item_count` and the preview would report that the actor could read
/// everything.
#[sqlx::test(migrations = "../../migrations")]
async fn the_selections_rendering_exits_refuse_the_viewer_that_produced_it(pool: PgPool) {
    let (scoped, bypass) = fixture::bypass(&pool).await;
    let (author, _group) = fixture::seed_agent_with_group(&pool, "split").await;
    let claim = fixture::seed_public_claim(&pool, author, "split subject").await;
    let selection = UnfilteredSelection::from_selected(vec![SelectedClaim {
        claim_id: claim,
        depth: 0,
        via: "seed".to_string(),
    }]);
    let mut conn = scoped.inner().acquire().await.expect("acquire");

    assert!(
        matches!(
            selection.visible_count(&mut conn, &bypass).await,
            Err(SelectionError::Refused(
                SelectionRefusal::BypassViewerInRenderingPass
            ))
        ),
        "not_visible_to_actor's denominator must not be computed under the selection authority"
    );
    assert!(
        matches!(
            selection.render_previews(&mut conn, &bypass, 25).await,
            Err(SelectionError::Refused(
                SelectionRefusal::BypassViewerInRenderingPass
            ))
        ),
        "the sample must not be rendered under the selection authority"
    );
    assert!(
        matches!(
            selection
                .render_boundary_edges(&mut conn, &bypass, 25)
                .await,
            Err(SelectionError::Refused(
                SelectionRefusal::BypassViewerInRenderingPass
            ))
        ),
        "the boundary sample must not be rendered under the selection authority"
    );

    // CALIBRATION: the COUNT exits are not refused. Counts are deliberately not
    // re-filtered — re-filtering them would report a plan smaller than the one
    // that will be applied — so a blanket refusal on the type would be wrong.
    assert_eq!(selection.item_count(), 1);
    selection
        .boundary_edge_counts(&mut conn, &bypass)
        .await
        .expect("the boundary COUNT runs under the selection authority, by design");
}

// ===========================================================================
// Fixtures local to this file
// ===========================================================================

/// A target group that satisfies migration 081's plan guard, its instance-admin
/// actor, and two claims to select.
struct World {
    actor: Uuid,
    co_admin: Uuid,
    target_group: Uuid,
    seed_claim: Uuid,
}

/// What `freeze_a_plan` wrote.
struct Frozen {
    plan_id: Uuid,
    digest: [u8; 32],
}

impl World {
    async fn seed(pool: &PgPool) -> Self {
        let (actor, target_group) = fixture::seed_agent_with_group(pool, "pp-actor").await;
        fixture::grant_app_privileges(pool, "epigraph_app").await;

        // 081's guard: the target group must be >= 24h old and carry >= 2 live
        // admins other than the plan's author.
        sqlx::query("UPDATE groups SET created_at = now() - interval '48 hours' WHERE id = $1")
            .bind(target_group)
            .execute(pool)
            .await
            .expect("backdate the target group");
        let co_admin = add_admin(pool, target_group, "pp-co-1").await;
        add_admin(pool, target_group, "pp-co-2").await;

        let seed_claim =
            fixture::seed_group_claim(pool, actor, target_group, "the seeded claim").await;
        let successor = fixture::seed_group_claim(pool, actor, target_group, "its successor").await;
        // A `supersedes` link, so the mandatory content-lineage hull has
        // something to contribute and the frozen set is not merely the seeds.
        sqlx::query("UPDATE claims SET supersedes = $2 WHERE id = $1")
            .bind(successor)
            .bind(seed_claim)
            .execute(pool)
            .await
            .expect("link the successor");

        let maint = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
        InstanceAdminRepository::grant(&maint, actor, None, Some("plan-policies"))
            .await
            .expect("grant the actor instance admin");

        Self {
            actor,
            co_admin,
            target_group,
            seed_claim,
        }
    }

    /// Run the selection and freeze it, exactly as `routes/privatization.rs`
    /// does: both on the maintenance connection, under a bypass viewer.
    async fn freeze_a_plan(&self, pool: &PgPool) -> Frozen {
        let (scoped, bypass) = fixture::bypass(pool).await;
        let _ = &scoped;
        let maint = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
        let mut conn = maint
            .acquire()
            .await
            .expect("acquire maintenance connection");

        let seeds = vec![self.seed_claim];
        let edge_types = vec!["derived_from".to_string()];
        let selection = PrivatizationRepository::select(
            &mut conn,
            &bypass,
            ClosureRequest {
                seeds: &seeds,
                edge_types: &edge_types,
                direction: ClosureDirection::Both,
                max_depth: 3,
                node_cap: 1000,
            },
            NO_TIMEOUT_CONCERN,
        )
        .await
        .expect("select");
        assert_eq!(
            selection.item_count(),
            2,
            "CALIBRATION: the hull must pull the successor in, or the freeze below writes only \
             the seed and the item-set assertions are about a one-row table"
        );

        let digest = selection.digest();
        let selector = serde_json::json!({ "seeds": { "ids": { "claims": [self.seed_claim] } } });
        let (plan_id, _created_at) = PrivatizationRepository::create_previewed_plan(
            &mut conn,
            NewPlan {
                mode: "restrict",
                target_group_id: self.target_group,
                selector: &selector,
                on_conflict: "abort",
                pad_to: 256,
                created_by: self.actor,
                plan_digest: &digest,
                item_count: i32::try_from(selection.item_count()).expect("small"),
                authors_losing_count: 0,
            },
        )
        .await
        .expect("create_previewed_plan on the maintenance connection");

        let frozen = selection
            .freeze_into(&mut conn, plan_id)
            .await
            .expect("freeze_into");
        assert_eq!(frozen, 2, "both selected claims must be frozen");

        Frozen { plan_id, digest }
    }
}

/// A downgraded `epigraph_app` connection stamped with `epigraph.principal_id`.
///
/// The plan tables' policy reads the principal and nothing else, so this is the
/// whole stamp those assertions need; `fully_stamped_app_conn` below adds the
/// group array for the reads that go through `claims_tenancy` / `edges_tenancy`.
async fn stamped_admin_conn(
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
        "the connection must really be downgraded, or FORCE is not in play and every plan-table \
         assertion in this file is vacuous"
    );
    assert!(
        !bypassrls,
        "epigraph_app must not hold BYPASSRLS, or the policy is not the control"
    );
    assert_eq!(
        observed,
        Some(principal),
        "the principal stamp must have taken, or 087's third disjunct is false for the wrong \
         reason"
    );
    conn
}

/// A downgraded `epigraph_app` connection stamped with BOTH the principal and
/// the live group array.
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

    let mut conn = stamped_admin_conn(pool, principal).await;
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

    let observed: Vec<Uuid> = sqlx::query_scalar("SELECT public.epigraph_session_groups()")
        .fetch_one(&mut *conn)
        .await
        .expect("group probe");
    assert_eq!(
        observed.len(),
        groups.len(),
        "the group stamp must have taken, or edges_tenancy sees an empty array and the positive \
         control below fails for the wrong reason"
    );
    conn
}

/// Add a live `role='admin'` membership to `group`, returning the new agent.
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
