//! `POST /api/v1/admin/privatization/plans` and the read surface over the plans
//! it persists.
//!
//! # What this file measures, and what it explicitly does not
//!
//! The handlers are called DIRECTLY, not over HTTP. `spawn_app` builds
//! `AppState` through `AppState::with_db`, which leaves `scoped` as `None`, and
//! both `AppState::read_as` and `AppState::maintenance_viewer` REFUSE rather
//! than falling back to the raw pool — so every one of these handlers would
//! return 500 through that fixture. `split_state` below is the same shape three
//! conversion shards already use for the same reason; the HTTP-level
//! (bearer-auth) fixture gap is recorded in `docs/tenancy/progress.json` with an
//! owner and this file does not close it.
//!
//! **The plan tables' RLS policy is NOT under test here.** `split_state`'s
//! `scoped` arm connects as the `#[sqlx::test]` superuser, which is
//! `rolbypassrls`, so migration 087's SELECT policies admit everything on it.
//! What IS under test here is the handler wiring, the authorization refusals,
//! and the sec-F7 response shape — the spliced viewer predicate in the rendering
//! pass survives a superuser connection, and it is what the
//! `not_visible_to_actor` arm below measures. The policy half is asserted on
//! downgraded connections in
//! `crates/epigraph-db/tests/privatization_plan_policies.rs`. Neither file is
//! sufficient alone.

mod viewer_fixture;

use axum::extract::{Path, Query, State};
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::privatization::{
    create_plan, get_plan, get_plan_items, list_plans, ClosureBody, CreatePlanRequest,
    PlanItemQuery, PlanListQuery, PlanSeeds, SeedIds, SeedPredicate,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::repos::instance_admin::InstanceAdminRepository;
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{downgraded_pool, scoped_pool, seed_agent_with_group, seed_group_claim};

// ===========================================================================
// The happy path, and the sec-F7 response shape.
// ===========================================================================

/// A plan is created, frozen and previewed; an item the actor cannot read
/// appears as a COUNT and contributes no id and no content.
///
/// This is FINAL-PLAN's PR-18 acceptance clause 1's `not_visible_to_actor` "as a
/// count with no ids", asserted at the shape the wire actually carries. Before
/// this slice the subtraction existed only in a test body — there was no
/// production code that assembled the figure.
///
/// The negative direction is the one that fails silently: "the preview reported
/// two items" is satisfied by a preview that also leaked both ids and their
/// content, so the assertions below are on the ABSENCE of the invisible claim's
/// id from `sample`, calibrated by the visible one's PRESENCE.
#[sqlx::test(migrations = "../../migrations")]
async fn a_preview_counts_what_the_actor_cannot_read_and_names_only_what_it_can(pool: PgPool) {
    let world = World::seed(&pool).await;

    // Two seeds: one the actor can read (its own group's), one it cannot
    // (private to a group it is not a member of).
    let (outsider, elsewhere) = seed_agent_with_group(&pool, "pr-elsewhere").await;
    let unreadable = seed_group_claim(&pool, outsider, elsewhere, "not for you").await;
    let readable = seed_group_claim(&pool, world.actor, world.target_group, "yours").await;

    // A claim just OUTSIDE the selection, joined to a selected one by a
    // relationship the default closure does not traverse. This is what makes
    // the boundary survey and the omitted-edge-type warning non-zero — asserted
    // below at the RESPONSE shape, which is the thing this slice adds. The repo
    // primitives behind them were already covered in `privatization_boundary.rs`;
    // what was not covered is that `create_plan` assembles them into the body.
    let neighbour = seed_group_claim(&pool, world.actor, world.target_group, "next door").await;
    viewer_fixture::seed_edge(&pool, readable, neighbour).await;

    let state = split_state(&pool).await;
    let viewer = Viewer::resolve(&pool, world.actor)
        .await
        .expect("resolve the actor");

    // CALIBRATION: the actor's own viewer really cannot read the other group's
    // claim. Without this the count below is zero for the wrong reason.
    assert!(
        !viewer
            .group_bind()
            .is_some_and(|groups| groups.contains(&elsewhere)),
        "CALIBRATION: the actor must not be a member of the other group"
    );

    let (status, Json(preview)) = create_plan(
        ViewerExtractor(viewer),
        State(state.clone()),
        Some(axum::Extension(world.auth())),
        Json(plan_body(world.target_group, vec![readable, unreadable])),
    )
    .await
    .expect("the plan must be created");

    assert_eq!(status, axum::http::StatusCode::CREATED);
    assert_eq!(
        preview.counts.total, 2,
        "selection is UNFILTERED: both seeds are in the plan, including the one the actor \
         cannot read. A selection narrowed to the actor would produce a plan that misses the \
         rows privatization exists to find"
    );
    assert_eq!(
        preview.counts.frozen, 2,
        "both selected claims must be frozen into privatization_plan_items"
    );
    assert_eq!(
        preview.counts.not_visible_to_actor, 1,
        "the item the actor cannot read must be COUNTED"
    );
    assert!(
        preview.plan_digest.starts_with("b3:"),
        "the digest an apply must echo is returned, tagged: {}",
        preview.plan_digest
    );

    let named: Vec<Uuid> = preview.sample.iter().map(|s| s.id).collect();
    assert!(
        named.contains(&readable),
        "CALIBRATION: the sample must name the claim the actor CAN read, or the absence below is \
         satisfied by an empty sample"
    );
    assert!(
        !named.contains(&unreadable),
        "an item the actor cannot read must contribute a count and NOTHING else — no id, no \
         content, no placeholder. It appeared in the sample: {named:?}"
    );
    assert!(
        !preview
            .sample
            .iter()
            .any(|s| s.preview.contains("not for you")),
        "no byte of an unreadable claim's content may reach the preview"
    );
    assert!(
        preview
            .warnings
            .iter()
            .any(|w| w.contains("not visible to you")),
        "the operator is told there is something they cannot see: {:?}",
        preview.warnings
    );

    // ---- The three OTHER sub-reports acceptance clause 1 names, at the
    // response shape rather than at the repo primitive. ----
    assert_eq!(
        preview.counts.authors_losing_own_claims, 1,
        "exactly the outsider loses access to their own claim; the actor is a member of the \
         target group and so loses nothing. A fixture where both authors were members would \
         satisfy `>= 0` and measure nothing"
    );
    assert!(
        preview.requires_second_approver,
        "an author losing their own claims is one of the two thresholds, so the flag the counts \
         drive must be set"
    );
    assert_eq!(
        preview.boundary_edges.claim_to_claim, 1,
        "the edge from a selected claim to the neighbour outside the selection straddles the \
         boundary and must be surveyed: {:?}",
        preview.boundary_edges
    );
    assert_eq!(
        preview.boundary_edges.by_relationship.get("supports"),
        Some(&1),
        "the survey is keyed BY RELATIONSHIP, so an operator can see which kind of link is being \
         cut: {:?}",
        preview.boundary_edges.by_relationship
    );
    assert!(
        preview
            .warnings
            .iter()
            .any(|w| w.contains("supports") && w.contains("omits")),
        "`supports` was not traversed and one claim hangs off it, so the operator is warned \
         rather than left to discover it after the apply: {:?}",
        preview.warnings
    );

    // The persisted plan reads back, and its item page applies the SAME
    // rendering pass: the unreadable item is a count there too.
    let Json(items) = get_plan_items(
        ViewerExtractor(
            Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve again"),
        ),
        State(state.clone()),
        Some(axum::Extension(world.auth())),
        Path(preview.plan_id),
        Query(PlanItemQuery::default()),
    )
    .await
    .expect("the item page must be served");
    assert_eq!(items.not_visible_to_actor, 1);
    assert_eq!(items.items.len(), 1);
    assert_eq!(items.items[0].id, readable);

    let Json(listed) = list_plans(
        ViewerExtractor(
            Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve again"),
        ),
        State(state),
        Some(axum::Extension(world.auth())),
        Query(PlanListQuery::default()),
    )
    .await
    .expect("the list must be served");
    assert!(listed.plans.iter().any(|p| p.plan_id == preview.plan_id));
}

/// **Paging the frozen set one row at a time yields no id the actor may not
/// read — in the body OR in the cursor.**
///
/// The item page is the one surface where the sec-F7 rule has to hold across
/// REQUESTS rather than within one response: `not_visible_to_actor` says some
/// rows on this page must be counted and not named, and a pagination token is
/// as much a response field as `items` is. `PlanItemQuery::default()` cannot
/// see this — it asks for 100 rows over a two-row plan, so `rows.len() != limit`
/// and the handler never emits a cursor at all.
///
/// So this walks the whole set at `limit = 1`, which is a legal request, and
/// asserts on every page that neither the items nor `next_cursor` mentions the
/// claim the actor cannot read. The calibration is that the walk actually
/// terminates by exhausting the set and that it DID surface the readable claim
/// — without it, "no unreadable id appeared" is satisfied by a walk that
/// returned nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn walking_the_item_pages_one_at_a_time_names_no_id_the_actor_cannot_read(pool: PgPool) {
    let world = World::seed(&pool).await;
    let (outsider, elsewhere) = seed_agent_with_group(&pool, "pr-page-elsewhere").await;
    let unreadable = seed_group_claim(&pool, outsider, elsewhere, "not for you").await;
    let readable = seed_group_claim(&pool, world.actor, world.target_group, "yours").await;

    let state = split_state(&pool).await;
    let (_, Json(preview)) = create_plan(
        ViewerExtractor(Viewer::resolve(&pool, world.actor).await.expect("resolve")),
        State(state.clone()),
        Some(axum::Extension(world.auth())),
        Json(plan_body(world.target_group, vec![readable, unreadable])),
    )
    .await
    .expect("the plan must be created");
    assert_eq!(
        preview.counts.total, 2,
        "CALIBRATION: the frozen set must hold both claims, or there is nothing to page over"
    );

    let mut cursor: Option<String> = None;
    let mut pages = 0;
    let mut named: Vec<Uuid> = Vec::new();
    let mut counted = 0i64;
    let mut tokens: Vec<String> = Vec::new();

    loop {
        pages += 1;
        assert!(
            pages <= 8,
            "the walk must terminate; it did not by page {pages}"
        );
        let Json(page) = get_plan_items(
            ViewerExtractor(Viewer::resolve(&pool, world.actor).await.expect("resolve")),
            State(state.clone()),
            Some(axum::Extension(world.auth())),
            Path(preview.plan_id),
            Query(PlanItemQuery {
                limit: Some(1),
                cursor: cursor.clone(),
            }),
        )
        .await
        .expect("the item page must be served");

        named.extend(page.items.iter().map(|i| i.id));
        counted += page.not_visible_to_actor;
        if let Some(token) = page.next_cursor.clone() {
            tokens.push(token.clone());
            cursor = Some(token);
        } else {
            break;
        }
    }

    assert!(
        named.contains(&readable),
        "CALIBRATION: the walk must have named the claim the actor CAN read, or the absence below \
         is satisfied by a walk that returned nothing. Named: {named:?}"
    );
    assert!(
        !named.contains(&unreadable),
        "an item the actor cannot read must never be named, on any page: {named:?}"
    );
    assert_eq!(
        counted, 1,
        "it is COUNTED instead, exactly once across the walk"
    );

    let forbidden = unreadable.to_string();
    assert!(
        !tokens.iter().any(|t| t.contains(&forbidden)),
        "the pagination token must carry a position and not an entity id; tokens were {tokens:?}"
    );
    assert!(
        !tokens.is_empty(),
        "CALIBRATION: at least one page must have emitted a token, or the assertion above is \
         vacuous"
    );

    // A caller-chosen ordering key is not a cursor. The handler accepts a
    // position and nothing else, so the previous spelling is a 400 rather than
    // a query it will answer.
    let err = get_plan_items(
        ViewerExtractor(Viewer::resolve(&pool, world.actor).await.expect("resolve")),
        State(state),
        Some(axum::Extension(world.auth())),
        Path(preview.plan_id),
        Query(PlanItemQuery {
            limit: Some(1),
            cursor: Some(format!("claim:{unreadable}")),
        }),
    )
    .await
    .expect_err("an entity id is not a cursor this handler accepts");
    assert!(
        matches!(&err, ApiError::BadRequest { message } if message.contains("cursor")),
        "expected the malformed-cursor refusal, got {err:?}"
    );
}

// ===========================================================================
// The three-condition check, on the CREATE path and on a READ path.
// ===========================================================================

/// A caller with the scope but no `instance_admins` row is refused.
///
/// Condition 1 is a claim the token makes about itself; condition 2 is the
/// instance's own record, and it is what makes condition 1 insufficient rather
/// than decorative.
#[sqlx::test(migrations = "../../migrations")]
async fn the_scope_alone_does_not_authorise_a_plan(pool: PgPool) {
    let world = World::seed(&pool).await;
    let claim = seed_group_claim(&pool, world.actor, world.target_group, "subject").await;
    let state = split_state(&pool).await;

    // A second principal holding the same token scopes, with no grant.
    let (ungranted, _) = seed_agent_with_group(&pool, "pr-ungranted").await;
    let auth = auth_for(ungranted);
    assert!(
        auth.has_scope("instance:admin"),
        "CALIBRATION: the refusal below must be attributable to condition 2, so condition 1 must \
         pass"
    );

    let err = create_plan(
        ViewerExtractor(Viewer::resolve(&pool, ungranted).await.expect("resolve")),
        State(state),
        Some(axum::Extension(auth)),
        Json(plan_body(world.target_group, vec![claim])),
    )
    .await
    .expect_err("a caller with no instance_admins row must be refused");
    assert!(
        matches!(&err, ApiError::Forbidden { reason } if reason.contains("instance administrator")),
        "expected the instance-admin refusal, got {err:?}"
    );
}

/// **`GET /plans/:id` carries the same check as `POST /plans` (sec F7b).**
///
/// FINAL-PLAN §6.5.2 point 2 records that the previous revision authorised
/// creation correctly and read loosely, and that this is what shipped the
/// cross-tenant read oracle. The actor here creates a plan legitimately, then a
/// SECOND instance admin — one who does not administer the target group — asks
/// for it by id and is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_read_endpoint_refuses_an_instance_admin_who_does_not_administer_the_target(
    pool: PgPool,
) {
    let world = World::seed(&pool).await;
    let claim = seed_group_claim(&pool, world.actor, world.target_group, "subject").await;
    let state = split_state(&pool).await;

    let (_, Json(preview)) = create_plan(
        ViewerExtractor(Viewer::resolve(&pool, world.actor).await.expect("resolve")),
        State(state.clone()),
        Some(axum::Extension(world.auth())),
        Json(plan_body(world.target_group, vec![claim])),
    )
    .await
    .expect("the plan must be created");

    // A live instance admin with no membership of the target group.
    let (outsider, _own) = seed_agent_with_group(&pool, "pr-outsider").await;
    let maint = downgraded_pool(&pool, "epigraph_maintenance").await;
    InstanceAdminRepository::grant(&maint, outsider, None, Some("outsider"))
        .await
        .expect("grant the outsider");
    // CALIBRATION: the outsider really is an instance admin, so the refusal is
    // attributable to the target-group conditions and not to condition 2.
    assert!(
        InstanceAdminRepository::is_active(&pool, outsider)
            .await
            .expect("is_active"),
        "CALIBRATION: the outsider must be a live instance admin"
    );

    let err = get_plan(
        ViewerExtractor(Viewer::resolve(&pool, outsider).await.expect("resolve")),
        State(state),
        Some(axum::Extension(auth_for(outsider))),
        Path(preview.plan_id),
    )
    .await
    .expect_err("instance:admin alone must not read another admin's plan");
    assert!(
        matches!(err, ApiError::Forbidden { .. }),
        "expected a 403 from the target-group conditions, got {err:?}"
    );
}

/// A target group that is too young is refused, and the refusal names the
/// condition.
///
/// FINAL-PLAN §6.6 (sec F4): `POST /api/v1/groups` needs only `groups:write` and
/// inserts the creator as `role='admin'`, so without a maturity condition a
/// rogue instance admin manufactured a compliant target group in one request.
/// This is acceptance clause 5's HTTP half.
#[sqlx::test(migrations = "../../migrations")]
async fn a_target_group_younger_than_the_threshold_is_refused(pool: PgPool) {
    let world = World::seed(&pool).await;
    let claim = seed_group_claim(&pool, world.actor, world.target_group, "subject").await;
    let state = split_state(&pool).await;

    // Un-backdate the group. Everything else about the world is unchanged, so
    // the refusal is attributable to maturity alone.
    sqlx::query("UPDATE groups SET created_at = now() WHERE id = $1")
        .bind(world.target_group)
        .execute(&pool)
        .await
        .expect("re-date the target group");

    let err = create_plan(
        ViewerExtractor(Viewer::resolve(&pool, world.actor).await.expect("resolve")),
        State(state),
        Some(axum::Extension(world.auth())),
        Json(plan_body(world.target_group, vec![claim])),
    )
    .await
    .expect_err("a target group younger than the threshold must be refused");
    assert!(
        matches!(&err, ApiError::Forbidden { reason } if reason.contains("pre-exist")),
        "expected the maturity refusal, got {err:?}"
    );
}

// ===========================================================================
// Request validation.
// ===========================================================================

/// FINAL-PLAN §3.1's ceilings reach the wire as a 400, not as a truncation, and
/// a `saved_query` seed is a 501.
#[sqlx::test(migrations = "../../migrations")]
async fn the_request_ceilings_and_the_unimplemented_selector_reach_the_wire(pool: PgPool) {
    let world = World::seed(&pool).await;
    let claim = seed_group_claim(&pool, world.actor, world.target_group, "subject").await;
    let state = split_state(&pool).await;

    let mut body = plan_body(world.target_group, vec![claim]);
    body.closure = Some(ClosureBody {
        edge_types: None,
        direction: None,
        max_depth: Some(7),
        node_cap: None,
    });
    let err = create_plan(
        ViewerExtractor(Viewer::resolve(&pool, world.actor).await.expect("resolve")),
        State(state.clone()),
        Some(axum::Extension(world.auth())),
        Json(body),
    )
    .await
    .expect_err("max_depth above the system ceiling must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message } if message.contains("max_depth")),
        "the ceiling must be a 400 naming the parameter, not a clamp; got {err:?}"
    );

    let mut body = plan_body(world.target_group, vec![claim]);
    body.seeds = PlanSeeds {
        ids: None,
        predicate: None,
        saved_query: Some(serde_json::json!({ "name": "nda-corpus" })),
    };
    let err = create_plan(
        ViewerExtractor(Viewer::resolve(&pool, world.actor).await.expect("resolve")),
        State(state),
        Some(axum::Extension(world.auth())),
        Json(body),
    )
    .await
    .expect_err("a saved_query seed must be refused");
    assert!(
        matches!(&err, ApiError::NotImplemented { feature } if feature.contains("saved_query")),
        "FINAL-PLAN §6.5.1 ships the schema slot and not the semantics; got {err:?}"
    );
}

/// A seed set larger than `closure.node_cap` is REFUSED, not truncated.
///
/// The predicate arm goes through `ClaimRepository::list_by_labels`, which takes
/// a `LIMIT` and no total ordering — so a truncated seed set would be an
/// ARBITRARY subset, frozen into a plan and digested as if the operator had
/// chosen it. This is the same refusal `select_closure` makes about the closure,
/// one layer earlier, and it is the direction FINAL-PLAN §3.1 names: a 400, not
/// a truncation.
///
/// Both arms are asserted. The `ids` arm is exact by construction and refuses on
/// length; the `predicate` arm cannot know the true cardinality without asking
/// for one row more than the cap allows.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seed_set_larger_than_the_node_cap_is_refused_rather_than_truncated(pool: PgPool) {
    let world = World::seed(&pool).await;
    let state = split_state(&pool).await;

    let mut labelled = Vec::new();
    for i in 0..3 {
        let id = seed_group_claim(
            &pool,
            world.actor,
            world.target_group,
            &format!("labelled {i}"),
        )
        .await;
        sqlx::query("UPDATE claims SET labels = ARRAY['pr-overflow'] WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("label the claim");
        labelled.push(id);
    }

    let tiny_cap = ClosureBody {
        edge_types: None,
        direction: None,
        max_depth: None,
        node_cap: Some(2),
    };

    // CALIBRATION: the same predicate under a cap that FITS is accepted, so the
    // refusals below are attributable to the cap and not to the selector.
    let mut ok_body = plan_body(world.target_group, vec![]);
    ok_body.seeds = predicate_seeds();
    ok_body.closure = Some(ClosureBody {
        node_cap: Some(10),
        ..tiny_cap.clone()
    });
    let (status, _) = create_plan(
        ViewerExtractor(Viewer::resolve(&pool, world.actor).await.expect("resolve")),
        State(state.clone()),
        Some(axum::Extension(world.auth())),
        Json(ok_body),
    )
    .await
    .expect("CALIBRATION: three seeds under a cap of ten must be accepted");
    assert_eq!(status, axum::http::StatusCode::CREATED);

    let mut body = plan_body(world.target_group, vec![]);
    body.seeds = predicate_seeds();
    body.closure = Some(tiny_cap.clone());
    let err = create_plan(
        ViewerExtractor(Viewer::resolve(&pool, world.actor).await.expect("resolve")),
        State(state.clone()),
        Some(axum::Extension(world.auth())),
        Json(body),
    )
    .await
    .expect_err("a predicate matching more claims than node_cap must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message } if message.contains("seeds.predicate")),
        "the refusal must name the SELECTOR, so the operator narrows the right thing; got {err:?}"
    );

    let mut body = plan_body(world.target_group, labelled);
    body.closure = Some(tiny_cap);
    let err = create_plan(
        ViewerExtractor(Viewer::resolve(&pool, world.actor).await.expect("resolve")),
        State(state),
        Some(axum::Extension(world.auth())),
        Json(body),
    )
    .await
    .expect_err("an explicit id list longer than node_cap must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message } if message.contains("seeds.ids")),
        "expected the ids-arm refusal, got {err:?}"
    );
}

// ===========================================================================
// Fixtures local to this file
// ===========================================================================

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped.
///
/// The same shape `claims_query_scoped_read.rs`, `lineage_scoped_read.rs` and
/// `search_voids_methods_scoped_read.rs` build, and for the same reason: it is
/// the only `AppState` in the test suite on which `read_as` and
/// `maintenance_viewer` do not refuse.
async fn split_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let scoped = scoped_pool(pool).await;

    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);

    assert!(
        state.scoped.is_some(),
        "CALIBRATION: AppState.scoped must be populated, or read_as refuses and every handler \
         here returns 500"
    );
    let raw_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&state.db_pool)
        .await
        .expect("current_user on the raw pool");
    assert_eq!(
        raw_user, "epigraph_app",
        "CALIBRATION: AppState.db_pool must be DOWNGRADED, or a handler reverted to it is \
         invisible"
    );
    state
}

/// The seeded world: an instance admin who administers a mature target group
/// with two other live admins.
struct World {
    actor: Uuid,
    target_group: Uuid,
}

impl World {
    async fn seed(pool: &PgPool) -> Self {
        let (actor, target_group) = seed_agent_with_group(pool, "pr-actor").await;
        viewer_fixture::grant_app_privileges(pool, "epigraph_app").await;

        sqlx::query("UPDATE groups SET created_at = now() - interval '48 hours' WHERE id = $1")
            .bind(target_group)
            .execute(pool)
            .await
            .expect("backdate the target group");
        add_admin(pool, target_group, "pr-co-1").await;
        add_admin(pool, target_group, "pr-co-2").await;

        let maint = downgraded_pool(pool, "epigraph_maintenance").await;
        InstanceAdminRepository::grant(&maint, actor, None, Some("route-test"))
            .await
            .expect("grant the actor instance admin");

        Self {
            actor,
            target_group,
        }
    }

    fn auth(&self) -> AuthContext {
        auth_for(self.actor)
    }
}

/// An `AuthContext` carrying `instance:admin` for `agent`.
fn auth_for(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type: ClientType::Agent,
        scopes: vec!["instance:admin".to_string(), "claims:read".to_string()],
        jti: Uuid::new_v4(),
    }
}

/// A minimal `restrict` plan body over explicit seed ids.
fn plan_body(target_group_id: Uuid, claims: Vec<Uuid>) -> CreatePlanRequest {
    CreatePlanRequest {
        mode: None,
        target_group_id,
        seeds: PlanSeeds {
            ids: Some(SeedIds { claims }),
            predicate: None,
            saved_query: None,
        },
        closure: None,
        on_conflict: None,
        pad_to: None,
    }
}

/// A `predicate` seed arm over the label the overflow test stamps.
fn predicate_seeds() -> PlanSeeds {
    PlanSeeds {
        ids: None,
        predicate: Some(SeedPredicate {
            labels: vec!["pr-overflow".to_string()],
            exclude_labels: Vec::new(),
            current_only: Some(true),
            agent_id: None,
            properties_contains: None,
            created_before: None,
        }),
        saved_query: None,
    }
}

/// Add a live `role='admin'` membership to `group`.
async fn add_admin(pool: &PgPool, group: Uuid, label: &str) -> Uuid {
    let (agent, _) = seed_agent_with_group(pool, label).await;
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
