//! Conversion shard 5's converted handlers serve every statement of a request on
//! ONE viewer-stamped connection, and a read that has a viewer to spend
//! suppresses on it.
//!
//! # What this file is, in the series
//!
//! Conversion shard 5 against `D-PR17-read-guards-widen-under-rls`: 17 sites
//! across five route files (`political.rs` 7, `context.rs` 4, `perspective.rs`
//! 3, `graph_neighborhood.rs` 2, `structural.rs` 1). It copies the template
//! PR-28 established in `claims_query_scoped_read.rs`, PR-29 carried into
//! `search_voids_methods_scoped_read.rs` and shard 4 into
//! `belief_computation_scoped_read.rs` — direct `async fn` invocation, a
//! CALIBRATION arm on every negative assertion, and
//! `viewer_fixture::downgraded_pool` for `AppState.db_pool`.
//!
//! # THE AUTHORITY TRAP, AND WHAT THIS FILE DOES ABOUT IT
//!
//! `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` AND
//! the table owner, so **no RLS policy filters anything on the pool it hands
//! you**. And since `f20b7c1b`, `AppState::with_scoped_pool` sets
//! `db_pool = scoped.inner()`, so on the `spawn_app` fixture the converted and
//! the unconverted arms are the SAME POOL and reverting a site to
//! `&state.db_pool` changes not one observable row.
//!
//! That is why the pre-existing HTTP binaries over these endpoints —
//! `structural_features_authz.rs`, `graph_neighborhoods_test.rs`,
//! `tenant_isolation_http.rs` — **are this shard's COUNTERFACTUAL and not its
//! instrument.** They stay green on a planted tree by construction, which is
//! precisely what makes them useful: they show the control added here is
//! load-bearing rather than redundant.
//!
//! [`split_state`] is the instrument. It gives `AppState.db_pool` its own pool
//! whose every connection is `SET SESSION AUTHORIZATION epigraph_app` in
//! `after_connect`, while `AppState.scoped` holds an ordinary `ScopedPool`. So
//! `db_pool != scoped.inner()`, the raw arm is FILTERED and unstamped, and
//! reverting a converted site is observable.
//!
//! # Coverage, stated per HANDLER because the fraction is ambiguous
//!
//! Two arms drive 4 of the shard's converted sites — but note the unit
//! before re-deriving that number. It counts `.db_pool` SITES, the unit the
//! ratchet uses (3 + 1 across the two arms below); counted as repo
//! FUNCTIONS driven it is a different integer, and an earlier revision of this
//! section left which one it meant to inference.
//!
//! The shortfall is a fixture gap rather than a judgement about which sites
//! matter. `epigraph-db/tests/viewer_fixture.rs` seeds agents, groups, claims,
//! edges, evidence and reasoning traces — and has **no seeder for `contexts`,
//! `perspectives`, `graph_neighborhoods`, `graph_cluster_runs` or
//! `claim_neighborhood_membership`**. The sites in `context.rs`,
//! `perspective.rs` and `graph_neighborhood.rs` are therefore unreachable from
//! this fixture without authoring five new seeders, which is a larger and
//! separable piece of work than the conversion it would cover. Their module
//! docs say so rather than implying coverage they do not have.
//!
//! **THE UNCOVERED SET, NAMED BY HANDLER RATHER THAN BY FILE.**
//! `graph_neighborhood.rs::claim_compound_neighborhood` and the `context.rs` /
//! `perspective.rs` handlers are executed by no arm here. Every repo method
//! they reach was already generic over `PgExecutor`, so `&mut PgConnection`
//! satisfies it and the change in each is an executor swap — which bounds the
//! runtime risk but does not make the coverage statement any less owed.
//!
//! **The political handlers are gone.** Seven of the shard's 17 sites were in
//! `routes/political.rs`. The political-monitoring module was deleted from the
//! kernel (backlog bd13e0e0) and its arms here (`claim_genealogy` twice,
//! `compare_agents`) went with it; `epistemic_profile`, the one handler a
//! kernel client reads, moved to `routes/agents.rs` (backlog a1dd9225) and
//! keeps its arm.
//!
//! The asymmetry runs the other way too, and the blanket file-level claim was
//! CONSERVATIVE for one of them: `graph_neighborhood.rs::expand` is driven
//! end-to-end by three HTTP arms in `graph_neighborhoods_test.rs` through
//! `spawn_app`. That is functional coverage, not tenancy coverage — those arms
//! cannot observe suppression, for the authority reason above — but a `read_as`
//! refusal in `expand` would have failed them.
//!
//! | route | sites driven | arm |
//! |---|---|---|
//! | `agents.rs::epistemic_profile` (moved from `political.rs`, backlog a1dd9225) | `AgentRepository::get_by_id`, `AgentProfileRepository::{get_agent_profile_claims, get_agent_evidence_distribution}` | [`epistemic_profile_counts_the_viewers_own_group_private_claim`] |
//! | `structural.rs::get_structural_features` | nine `StructuralRepository` reads on one connection | [`structural_features_counts_the_viewers_own_group_private_claim`] |
//!
//! # What IS and is NOT proven here
//!
//! `ScopedPoolOptions` exposes no `after_connect`, so the SCOPED arm is still a
//! superuser session and the positive assertions observe the in-query `$V`
//! predicate on the converted path, not migration 077's policies. That
//! limitation is inherited from every file this one copies and is recorded on
//! `D-PR17-request-path-never-stamps-session-gucs::pr26_disposition`.
//!
//! **The UNCONVERTED side is what these arms prove, and they prove it directly.**
//! Reverting a converted site to `&state.db_pool` puts the read on a session the
//! RLS policies filter with no `epigraph.group_ids` to admit the viewer's own
//! group — while the viewer's group is still bound into `$V` on that same
//! statement, so the in-query predicate would have returned the row. Only a
//! row-level policy can have removed it. That is the non-bypass-role,
//! principal-set, groups-deliberately-empty condition the acceptance asks for,
//! observed rather than deferred.
//!
//! Shard 5 ships no `epigraph-db/tests/*_policy.rs` sibling, for the same
//! fixture reason the coverage fraction gives; `F-SHARD4-A4` already owns that
//! gap and this shard neither closes nor widens it.

mod common;
mod viewer_fixture;

use axum::extract::{Path, Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::agents::{epistemic_profile, EpistemicProfileParams};
use epigraph_api::routes::structural::{get_structural_features, StructuralFeaturesQuery};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_auth::{AuthContext, ClientType};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    downgraded_pool, scoped_pool, seed_agent_with_group, seed_group_claim, seed_public_claim,
};

// ── The instrument ──

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped.
///
/// The asymmetry IS the instrument: a converted site reads through `scoped` and
/// works; the same site reverted to `&state.db_pool` reads through a session the
/// RLS policies filter, with no `epigraph.group_ids` to admit the viewer's own
/// group, and loses the rows.
///
/// This is the seventh hand-copy of this body in `crates/epigraph-api/tests/`.
/// The duplication is real and is registered; it is copied rather than
/// canonicalised because promoting it is a change to the shared fixture whose
/// reach is the subject of an open entry, and bundling that into a conversion
/// shard would put two unrelated decisions in one diff.
async fn split_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let scoped = scoped_pool(pool).await;

    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);

    assert!(
        state.scoped.is_some(),
        "CALIBRATION: AppState.scoped must be populated, or read_as refuses and \
         the handler cannot serve at all"
    );
    let raw_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&state.db_pool)
        .await
        .expect("current_user on the raw pool");
    assert_eq!(
        raw_user, "epigraph_app",
        "CALIBRATION: AppState.db_pool must be DOWNGRADED, or reverting a converted \
         site to it is invisible and the mutation proof is vacuous"
    );
    // Role IDENTITY is not role PRIVILEGE, and only the second is what makes
    // this instrument work. If `epigraph_app` were ever granted BYPASSRLS or
    // superuser, the raw arm would stop being filtered, every mutation proof in
    // this file -- and in the four predecessor files it copies this body from --
    // would pass while proving nothing, and no assertion above would notice.
    // Runtime `query_scalar`, deliberately not the macro, so `.sqlx/` is
    // unaffected.
    let raw_is_privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&state.db_pool)
    .await
    .expect("role privileges on the raw pool");
    assert!(
        !raw_is_privileged,
        "CALIBRATION: the raw pool's role must be subject to RLS -- neither superuser \
         nor BYPASSRLS. A privileged role here makes every negative arm in this file \
         vacuous while leaving them all green"
    );
    let scoped_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(state.scoped.as_ref().expect("scoped").inner())
        .await
        .expect("current_user on the scoped pool");
    assert_ne!(
        scoped_user, raw_user,
        "CALIBRATION: the scoped and raw arms must not be the same session — that \
         sameness is exactly what makes with_scoped_pool useless as a conversion fixture"
    );

    state
}

/// Resolved on the SUPERUSER pool, which is the simpler of two arms that both
/// work — and NOT, as a previous revision of this comment asserted, because
/// resolving on a filtered unstamped session would yield an empty group set.
///
/// # That claim was wrong, and it is corrected here rather than repeated
///
/// The earlier text reasoned from `group_memberships` being FORCE-protected: on
/// an unstamped session the principal and group GUCs are empty, so the policy's
/// membership and principal disjuncts are both false and the read returns
/// nothing. Every step of that is true OF A DIRECT READ OF THE TABLE, and
/// `Viewer::resolve` does not perform one. `GroupMembershipRepository::list_live_for_agent`
/// issues `SELECT group_id, role FROM public.epigraph_live_memberships($1)`,
/// and that function is `SECURITY DEFINER` owned by `epigraph_maintenance`, so
/// inside it the policy's `epigraph_definer_bypass()` disjunct is true and the
/// rows are returned. The arrangement is deliberate: migration 077 grants the
/// helper to `epigraph_app` precisely so resolution can run before the GUCs it
/// computes exist, which is recorded on
/// `D-PR17-live-memberships-is-parameterised-not-principal-bound`.
///
/// Measured on a genuinely filtered, unstamped `epigraph_app` session at
/// migration head 92 — `epigraph_bypass()` false, principal null, session groups
/// empty — the definer helper returned the agent's live membership while a
/// direct read of the same rows returned none. So the superuser pool here is a
/// convenience, the downgraded pool would resolve the same viewer, and no
/// assertion in this file rests on the difference.
async fn viewer_for(pool: &PgPool, agent: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
}

/// An `AuthContext` carrying `claims:admin`, which is what
/// `get_structural_features` requires to answer with EXACT counts.
///
/// Exact counts are not a convenience here, they are what makes the arm an
/// assertion at all: with the differential-privacy mechanism engaged the
/// response's count fields are Laplace-perturbed, and a noised count cannot
/// distinguish "the viewer's own group-private claim was suppressed" from "the
/// noise happened to subtract one". The scope also does NOT widen the viewer —
/// the handler's own doc says so, and the assertions below depend on that:
/// an admin still holds a `Scoped` viewer and still sees only its own visible
/// set.
fn admin_auth(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type: ClientType::Agent,
        scopes: vec!["claims:read".to_string(), "claims:admin".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

// ── agents.rs::epistemic_profile (moved out of political.rs, backlog a1dd9225) ──

/// `GET /api/v1/agents/:id/epistemic-profile` — the arm that drives the
/// executor widening on `AgentRepository::get_by_id` alongside the two
/// viewer-spliced `AgentProfileRepository` reads that share its connection.
///
/// The over-suppression direction is the one that catches a reversion to the raw
/// pool: with the handler reading `&state.db_pool`, the filtered unstamped
/// session has no `epigraph.group_ids` to admit the viewer's own group and the
/// agent's own group-private claim silently disappears from its own profile.
/// That direction is permanent and looks like data loss rather than like a leak,
/// which is why it is asserted first.
///
/// Note which half of this handler the assertion rests on. The
/// `AgentRepository::get_by_id` call is NOT provable by construction:
/// migration 077 gives `agents` the policy `agents_identity FOR SELECT USING
/// (true)`, so stamping that statement's connection narrows nothing and the
/// agent would be found either way. `claim_count` — a
/// `AgentProfileRepository::get_agent_profile_claims` read over `claims` and
/// `edges`, both FORCEd — is the provable half, and is what is asserted.
#[sqlx::test(migrations = "../../migrations")]
async fn epistemic_profile_counts_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s5-ep-mine").await;

    let public = seed_public_claim(&pool, agent, "s5 ep: my public claim").await;
    let private = seed_group_claim(&pool, agent, group, "s5 ep: my group-private claim").await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = epistemic_profile(
        ViewerExtractor(viewer),
        State(state),
        Path(agent),
        Query(EpistemicProfileParams {}),
    )
    .await
    .expect(
        "the viewer is entitled to read its own claims, so this must SERVE. A failure \
         here is the conversion itself: either `read_as` refused because the AppState \
         carries no ScopedPool, or a statement errored on the stamped connection",
    )
    .0;

    // `routes::agents::epistemic_profile` is the handler `routes/mod.rs` mounts
    // at this path; importing it from `agents` is what pins the move.
    assert_eq!(
        out.claim_count, 2,
        "CALIBRATION: an agent's own profile must count BOTH its public claim ({public}) \
         and the group-private claim ({private}) it authored in a group it belongs to. \
         A count of 1 is the fail-closed drift this arm exists to catch — the viewer's \
         group is bound into $V on that same statement, so the in-query predicate would \
         have returned the row, and only a row-level policy on an unstamped session can \
         have removed it"
    );
    assert!(
        out.claim_count > 0,
        "over-suppression check: a conversion that refuses every caller passes any \
         negative assertion, so the positive direction is asserted explicitly"
    );
}

// ── structural.rs ──

/// `GET /api/v1/structural-features/:owner_id` — the shard's densest single
/// conversion: one alias fanning into NINE sequential `StructuralRepository`
/// round-trips, now all on one stamped connection.
///
/// `node_counts` is the field asserted because it is the one whose SQL reaches
/// `claims` directly under a `{VISIBILITY:c}` marker, so the RLS policy and the
/// in-query predicate are both live on it. `epsilon = 0.0` with `claims:admin`
/// turns the differential-privacy noise OFF — a noised count cannot distinguish
/// suppression from perturbation, which would make this arm unfalsifiable.
#[sqlx::test(migrations = "../../migrations")]
async fn structural_features_counts_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s5-sf-mine").await;

    seed_public_claim(&pool, agent, "s5 sf: my public claim").await;
    seed_group_claim(&pool, agent, group, "s5 sf: my group-private claim").await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = get_structural_features(
        State(state),
        axum::Extension(admin_auth(agent)),
        ViewerExtractor(viewer),
        Path(agent),
        Query(StructuralFeaturesQuery { epsilon: 0.0 }),
    )
    .await
    .expect(
        "the caller holds claims:admin and is asking about its own subgraph, so this \
         must SERVE. A failure here is the conversion itself: either `read_as` refused \
         because the AppState carries no ScopedPool, or one of the nine statements \
         errored on the stamped connection",
    )
    .0;

    let claim_nodes = out
        .node_counts
        .iter()
        .find(|c| c.node_type == "claim")
        .map(|c| c.count)
        .unwrap_or(0);

    assert_eq!(
        claim_nodes, 2,
        "CALIBRATION: this agent's own subgraph contains both its public claim and the \
         group-private claim it authored in a group it belongs to, and with epsilon=0 \
         under claims:admin the count is EXACT. A count of 1 is the fail-closed drift \
         this arm exists to catch — the viewer's group is bound into $V on that same \
         statement, so only a row-level policy on an unstamped session can have removed \
         the row. got node_counts {:?}",
        out.node_counts
    );
    assert_eq!(
        out.owner_id, agent,
        "the response must describe the owner that was asked about"
    );
}
