//! Shared setup for the D4 apply/revert regressions.
//!
//! # Why these binaries live in `epigraph-api/tests` and not `epigraph-db/tests`
//!
//! FINAL-PLAN §8.6 names `privatization_resume.rs`, `privatization_revert.rs`
//! and `privatization_drift.rs` alongside the three selection binaries, which
//! are in `epigraph-db`. What they exercise is `epigraph_jobs::privatization`,
//! and `epigraph-jobs` depends on `epigraph-db` — so putting them there would
//! mean adding `epigraph-jobs` as a dev-dependency of `epigraph-db`. Cargo
//! permits that (dev-dependencies may cycle back), so it is not impossible; it
//! is a new build-graph edge from the schema crate to a consumer of it, for a
//! test.
//!
//! `epigraph-api` already depends on both crates and already carries a copy of
//! `viewer_fixture.rs`, so this is the placement that adds no build-graph edge
//! and no SIXTH copy of that fixture —
//! `F-PR28-viewer-fixture-duplication` is an open finding and a new copy would
//! worsen it. The divergence from §8.6's file paths is recorded in
//! `docs/tenancy/progress.json`.
//!
//! # What every test here has to get right about the pool
//!
//! `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` and
//! the table owner, so on that pool **no policy filters anything**. That is the
//! CORRECT pool for these binaries — the handler runs on the maintenance
//! connection, where `epigraph_bypass()` is true, so the superuser pool is a
//! faithful stand-in for it and the assertions here are about the handler's own
//! logic rather than about RLS. The policy-side assertions live in
//! `epigraph-db/tests/privatization_authz.rs` and
//! `privatization_plan_policies.rs`, which downgrade the role deliberately.

#![allow(dead_code)]

#[path = "viewer_fixture.rs"]
pub mod viewer_fixture;

use std::sync::Arc;

use epigraph_db::repos::instance_admin::InstanceAdminRepository;
use epigraph_db::repos::privatization::{
    ClosureDirection, ClosureRequest, NewPlan, PlanTransition, PrivatizationRepository,
    RESTATEMENT_EDGE_TYPES,
};
use epigraph_db::repos::security_event::{SecurityEventRepository, SecurityEventRow};
use epigraph_db::visibility::SystemReason;
use epigraph_db::ScopedPool;
use epigraph_jobs::privatization::{
    PrivatizationApplyHandler, PrivatizationRevertHandler, DISPATCH_EVENT_TYPE,
};
use epigraph_jobs::{EpiGraphJob, JobError, JobHandler, JobResult};
use sqlx::PgPool;
use uuid::Uuid;

/// The authorization world every D4 plan needs: an instance admin who
/// administers a MATURE target group with two other live admins.
///
/// Migration 081's `epigraph_privatization_plan_guard` fires on the plan INSERT
/// and enforces the maturity and plurality halves in the database, so a fixture
/// that skipped either would fail at `create_previewed_plan` rather than at the
/// assertion, and the failure would look like a bug in the code under test.
pub struct World {
    /// The instance admin who creates and dispatches plans.
    pub actor: Uuid,
    /// The group plans move claims into.
    pub target_group: Uuid,
}

impl World {
    /// Seed the world. Mirrors `privatization_routes.rs::World::seed`.
    pub async fn seed(pool: &PgPool) -> Self {
        let (actor, target_group) = viewer_fixture::seed_agent_with_group(pool, "d4-actor").await;
        viewer_fixture::grant_app_privileges(pool, "epigraph_app").await;

        sqlx::query("UPDATE groups SET created_at = now() - interval '48 hours' WHERE id = $1")
            .bind(target_group)
            .execute(pool)
            .await
            .expect("backdate the target group");
        add_admin(pool, target_group, "d4-co-1").await;
        add_admin(pool, target_group, "d4-co-2").await;

        let maint = viewer_fixture::downgraded_pool(pool, "epigraph_maintenance").await;
        InstanceAdminRepository::grant(&maint, actor, None, Some("apply-test"))
            .await
            .expect("grant the actor instance admin");

        Self {
            actor,
            target_group,
        }
    }
}

/// Add a live `role='admin'` membership to `group`.
pub async fn add_admin(pool: &PgPool, group: Uuid, label: &str) -> Uuid {
    let (agent, _) = viewer_fixture::seed_agent_with_group(pool, label).await;
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

/// A `derived_from` edge `source -> target`.
///
/// [`viewer_fixture::seed_edge`] makes a `supports` edge, which is the EPISTEMIC
/// tier and therefore defaults OFF in a privatization closure. The restatement
/// tier is what the closure traverses by default and what the drift rescan looks
/// along, so a fixture that used `supports` would build a graph the code under
/// test correctly ignores.
pub async fn derived_from(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'derived_from')",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("seed derived_from edge");
    id
}

/// Give `claim` a deterministic, position-varying embedding.
///
/// Acceptance clause 6 is BIT-IDENTITY on `content`, `content_tsv` and
/// `embedding` across a restrict round trip, and a NULL embedding satisfies
/// "unchanged" without exercising anything. A constant vector would too — every
/// element equal means a truncation or a re-quantisation is invisible — so the
/// value varies by position.
pub async fn give_embedding(pool: &PgPool, claim: Uuid) {
    sqlx::query(
        "UPDATE claims SET embedding = replace(replace( \
             (SELECT array_agg((i::float4) / 4096.0 ORDER BY i) \
                FROM generate_series(1, 1536) i)::text, '{', '['), '}', ']')::vector \
         WHERE id = $1",
    )
    .bind(claim)
    .execute(pool)
    .await
    .expect("give the claim an embedding");
}

/// `(content, content_tsv, embedding)` as text, for a bit-identity comparison.
pub async fn content_triple(pool: &PgPool, claim: Uuid) -> (String, String, Option<String>) {
    sqlx::query_as(
        "SELECT c.content, c.content_tsv::text, c.embedding::text \
           FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the claim's content columns")
}

/// A `ScopedPool` over the same database, which is what the handlers take.
pub async fn scoped(pool: &PgPool) -> Arc<ScopedPool> {
    Arc::new(viewer_fixture::scoped_pool(pool).await)
}

/// Run the real selection, persist the plan and freeze its items.
///
/// This is the production path — `PrivatizationRepository::select` followed by
/// `create_previewed_plan` and `UnfilteredSelection::freeze_into` — and not a
/// hand-written INSERT, because the digest and the frozen set have to agree or
/// the handler's fourth re-validation condition refuses everything and every
/// test below would pass for the wrong reason.
///
/// Returns `(plan_id, digest)`.
pub async fn create_plan(pool: &PgPool, world: &World, seeds: &[Uuid]) -> (Uuid, [u8; 32]) {
    create_plan_with_mode(pool, world, seeds, "restrict").await
}

/// [`create_plan`], with the plan `mode` chosen.
///
/// # `mode = "seal"` is reachable HERE and not through the route, deliberately
///
/// `routes/privatization.rs::create_plan` returns `501` for `seal` — the seal
/// path is PR-21's — but migration 080's `pp_mode_check` admits the value and
/// `pp_seal_needs_pad` only requires `pad_to > 0`, so the repository can persist
/// one. That is what lets the seal-specific refusal in `revert_plan` be measured
/// against a seal plan instead of against a `restrict` plan that never sealed
/// anything, which is the shape that would make the refusal look correct while
/// being a bug on the reversibility of every restrict plan.
pub async fn create_plan_with_mode(
    pool: &PgPool,
    world: &World,
    seeds: &[Uuid],
    mode: &str,
) -> (Uuid, [u8; 32]) {
    let scoped = viewer_fixture::scoped_pool(pool).await;
    let (mut conn, lease) = scoped
        .unscoped_for_maintenance(SystemReason::PrivatizationSelection)
        .await
        .expect("maintenance connection");
    let bypass =
        epigraph_db::visibility::Viewer::system(&lease, SystemReason::PrivatizationSelection);

    let edge_types: Vec<String> = RESTATEMENT_EDGE_TYPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let selection = PrivatizationRepository::select(
        &mut conn,
        &bypass,
        ClosureRequest {
            seeds,
            edge_types: &edge_types,
            direction: ClosureDirection::Both,
            max_depth: 3,
            node_cap: 10_000,
        },
        std::time::Duration::from_secs(30),
    )
    .await
    .expect("selection");

    let digest = selection.digest();
    let selector = serde_json::json!({ "seeds": { "ids": { "claims": seeds } } });
    let (plan_id, _) = PrivatizationRepository::create_previewed_plan(
        &mut conn,
        NewPlan {
            mode,
            target_group_id: world.target_group,
            selector: &selector,
            on_conflict: "abort",
            pad_to: 256,
            created_by: world.actor,
            plan_digest: &digest,
            item_count: i32::try_from(selection.item_count()).expect("fits"),
            authors_losing_count: 0,
        },
    )
    .await
    .expect("persist the plan");
    let frozen = selection
        .freeze_into(&mut conn, plan_id)
        .await
        .expect("freeze");
    assert_eq!(
        frozen,
        u64::try_from(selection.item_count()).expect("fits"),
        "CALIBRATION: the freeze must write every selected item, or the stored digest describes \
         a set the plan does not contain and every apply below is refused on condition 4"
    );
    (plan_id, digest)
}

/// Do what `POST …/apply` does to the database, without the HTTP layer.
///
/// The `security_events` row and the state flip in ONE transaction, exactly as
/// `routes/privatization.rs::dispatch` writes them, because FINAL-PLAN §6.5.5's
/// sixth re-validation condition compares the two and a fixture that wrote only
/// the flip would make every handler run refuse.
///
/// Returns the correlation id.
pub async fn dispatch(pool: &PgPool, world: &World, plan_id: Uuid, to_state: &str) -> String {
    let scoped = viewer_fixture::scoped_pool(pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(SystemReason::PrivatizationApply)
        .await
        .expect("maintenance connection");
    let correlation_id = Uuid::new_v4().simple().to_string();
    let mut tx = sqlx::Connection::begin(&mut *conn)
        .await
        .expect("dispatch transaction");

    SecurityEventRepository::log_conn(
        &mut tx,
        &SecurityEventRow {
            id: Uuid::new_v4(),
            event_type: DISPATCH_EVENT_TYPE.to_string(),
            agent_id: Some(world.actor),
            success: Some(true),
            details: serde_json::json!({ "plan_id": plan_id }),
            ip_address: None,
            user_agent: None,
            correlation_id: Some(correlation_id.clone()),
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .expect("write the dispatch security event");

    let from_states: Vec<String> = match to_state {
        "applying" => vec!["previewed".to_string(), "approved".to_string()],
        _ => vec![
            "applied".to_string(),
            "applied_with_drift".to_string(),
            "failed".to_string(),
        ],
    };
    let moved = PrivatizationRepository::transition_plan_conn(
        &mut tx,
        plan_id,
        PlanTransition::Dispatch {
            dispatched_by: world.actor,
            to_state,
            from_states: &from_states,
        },
    )
    .await
    .expect("flip the plan");
    assert_eq!(
        moved, 1,
        "CALIBRATION: the dispatch flip must move the plan"
    );

    tx.commit().await.expect("commit the dispatch");
    correlation_id
}

/// Build the apply job envelope.
pub fn apply_job(plan_id: Uuid, actor: Uuid, correlation_id: &str) -> epigraph_jobs::Job {
    EpiGraphJob::PrivatizationApply {
        plan_id,
        dispatched_by: actor,
        correlation_id: correlation_id.to_string(),
    }
    .into_job()
    .expect("serialise")
}

/// Build the revert job envelope.
pub fn revert_job(plan_id: Uuid, actor: Uuid, correlation_id: &str) -> epigraph_jobs::Job {
    EpiGraphJob::PrivatizationRevert {
        plan_id,
        dispatched_by: actor,
        correlation_id: correlation_id.to_string(),
    }
    .into_job()
    .expect("serialise")
}

/// Run the apply handler once, at the given batch size.
pub async fn run_apply(
    scoped: &Arc<ScopedPool>,
    job: &epigraph_jobs::Job,
    batch: i64,
) -> Result<JobResult, JobError> {
    PrivatizationApplyHandler::new(Arc::clone(scoped))
        .with_batch_size(batch)
        .handle(job)
        .await
}

/// Run the revert handler once, at the given batch size.
pub async fn run_revert(
    scoped: &Arc<ScopedPool>,
    job: &epigraph_jobs::Job,
    batch: i64,
) -> Result<JobResult, JobError> {
    PrivatizationRevertHandler::new(Arc::clone(scoped))
        .with_batch_size(batch)
        .handle(job)
        .await
}

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped.
///
/// The same shape `privatization_routes.rs::split_state` builds, and for the
/// same reason: it is the only `AppState` in the test suite on which `read_as`
/// and `maintenance_viewer` do not refuse.
pub async fn split_state(pool: &PgPool) -> epigraph_api::AppState {
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let scoped = viewer_fixture::scoped_pool(pool).await;
    let mut state = epigraph_api::AppState::with_db(raw, epigraph_api::ApiConfig::default());
    state.scoped = Some(scoped);
    assert!(
        state.scoped.is_some(),
        "CALIBRATION: AppState.scoped must be populated, or read_as refuses and every handler \
         here returns 500"
    );
    state
}

/// An `AuthContext` carrying `instance:admin` for `agent`.
pub fn auth_for(agent: Uuid) -> epigraph_auth::AuthContext {
    epigraph_auth::AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type: epigraph_auth::ClientType::Agent,
        scopes: vec!["instance:admin".to_string(), "claims:read".to_string()],
        jti: Uuid::new_v4(),
    }
}

/// A plan's `state`.
pub async fn plan_state(pool: &PgPool, plan_id: Uuid) -> String {
    sqlx::query_scalar("SELECT state FROM privatization_plans WHERE id = $1")
        .bind(plan_id)
        .fetch_one(pool)
        .await
        .expect("read the plan state")
}

/// A claim's `(visibility, owner_group_id)`.
pub async fn tenancy(pool: &PgPool, claim: Uuid) -> (String, Uuid) {
    sqlx::query_as("SELECT visibility::text, owner_group_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the claim tenancy")
}

/// A plan's items as `(entity_id, depth, state)`, in the apply order.
pub async fn items(pool: &PgPool, plan_id: Uuid) -> Vec<(Uuid, i32, String)> {
    sqlx::query_as(
        "SELECT entity_id, depth, state FROM privatization_plan_items \
          WHERE plan_id = $1 ORDER BY depth DESC, kind, entity_id",
    )
    .bind(plan_id)
    .fetch_all(pool)
    .await
    .expect("read the plan items")
}

/// Every `privatization_audit` action recorded for a plan.
pub async fn audit_actions(pool: &PgPool, plan_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM privatization_audit WHERE plan_id = $1 ORDER BY id")
        .bind(plan_id)
        .fetch_all(pool)
        .await
        .expect("read the audit trail")
}

/// The `(before_visibility, after_visibility)` pairs recorded for one entity
/// under one action.
///
/// The columns `GET /admin/privatization/audit` serves verbatim. Asserting the
/// ACTION alone would pass over a row that recorded no transition at all.
pub async fn audit_pairs(
    pool: &PgPool,
    plan_id: Uuid,
    entity_id: Uuid,
    action: &str,
) -> Vec<(Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT before_visibility, after_visibility FROM privatization_audit \
          WHERE plan_id = $1 AND entity_id = $2 AND action = $3 ORDER BY id",
    )
    .bind(plan_id)
    .bind(entity_id)
    .bind(action)
    .fetch_all(pool)
    .await
    .expect("read the audit before/after pair")
}

/// Write a `claim_encryption` row against a claim, as migration 060's
/// encrypted-subgraph feature does.
///
/// Migration 081's `claim_encryption_no_public_sealed` refuses the row while the
/// claim is `public`, so every caller seeds it AFTER the apply.
pub async fn encrypt_claim(pool: &PgPool, claim: Uuid, group: Uuid) {
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("seed the group key epoch the FK requires");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', decode('0badc0de', 'hex'))",
    )
    .bind(claim)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a claim_encryption row");
}

/// A plan's `(state, mode, authors_losing_count, item_count)`.
pub async fn plan_shape(pool: &PgPool, plan_id: Uuid) -> (String, String, i32, i32) {
    sqlx::query_as(
        "SELECT state, mode, authors_losing_count, item_count \
           FROM privatization_plans WHERE id = $1",
    )
    .bind(plan_id)
    .fetch_one(pool)
    .await
    .expect("read the plan shape")
}
