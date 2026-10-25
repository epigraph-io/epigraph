#![cfg(feature = "db")]
//! `POST /api/v1/frames/:id/evidence`'s edges and derived rows, ARMED, on the
//! APPLICATION ROLE (backlog fb9cff66).
//!
//! `submit_evidence` writes its BBA, frame assignment, cached belief and global
//! scoped belief on one viewer-stamped transaction (#611). Its other writes,
//! the claim -> frame `WITHIN_FRAME` edge, the claim -> context `SCOPED_BY`
//! edge, the perspective -> claim `CONTRIBUTES_TO` edge, the perspective-scoped
//! belief and the divergence record, ran on the raw pool. With that pool on the
//! application role, as in production, the edges trigger saw no session writer
//! and row security saw no writable group:
//! * on a GROUP claim every one of them was refused, silently (`let _`): the
//!   claim had no frame link, no perspective belief and no divergence record;
//! * on a PUBLIC claim the edges landed with NO writer group (unattributed;
//!   the claim -> frame and perspective -> claim edges world-owned), and the
//!   derived rows were refused.
//!
//! Both pools here are `epigraph_app` (`claim_routes_bind_the_caller.rs`'s
//! `app_role_state`), the database is armed (migration 122), and the handler
//! is invoked directly with the caller's viewer. The callers are a human
//! operator H, an agent live-linked to H (operated agents hold no HTTP token,
//! so this is the stdio shape of the same writer; its writes belong in H's
//! group HG), and a stranger linked to no human, with its own personal group.
//!
//! * `a_group_claims_edges_and_derived_rows_land_in_the_operators_group`: the
//!   positive case. Every edge and derived row exists, is owned by HG, and
//!   carries HG as its writer; no edge is world-owned. A second submission on
//!   the same (claim, frame), by H, persists its BBA although its
//!   GENERATED_BY INSERT is refused on the same transaction: the savepoint
//!   keeps that refusal from aborting it.
//! * `attribution_follows_the_caller_not_the_claims_owner`: an unlinked
//!   stranger on H's PUBLIC claim; its edges carry the STRANGER's writer
//!   group, not HG and not NULL. (Their OWNER is the edges trigger's call,
//!   not this handler's: migration 120 keeps a claim -> frame or perspective
//!   -> claim edge between public endpoints world-owned.)
//!   The operator's own submission on that public claim lands its
//!   perspective-scoped belief and divergence record.
//! * `a_community_scoped_belief_lands_in_the_operators_group`: step 17's
//!   community scope, on a group claim: the member BBAs are read as the
//!   caller and the community-scoped belief lands in HG.
//! * `a_caller_who_cannot_read_the_claim_writes_nothing`: the control. The
//!   stranger on H's GROUP claim gets the 404 and leaves no edge and no
//!   derived row behind.
//!
//! Two authorization checks on the same handler, which the stamped writes
//! above would otherwise carry further:
//! * `a_caller_cannot_submit_as_another_agent`: the body's `agent_id` must be
//!   the caller's own (403 otherwise); a writer member of HG naming H can
//!   neither attribute evidence to H nor overwrite H's BBA. Control: naming
//!   itself is stored.
//! * `an_omitted_agent_id_is_the_callers_own`: every BBA has an author. An
//!   omitted `agent_id` is the caller's, so two callers' agent-less
//!   submissions are two BBAs, and neither replaces the other.
//! * `a_perspective_the_caller_cannot_read_is_refused`: another group's
//!   private perspective is a 404 with nothing written;
//!   `the_callers_own_private_perspective_calibrates_its_evidence`: the
//!   caller's own private perspective is found, so its calibration applies.
//!
//! Verified to fail (remote, armed throwaway database):
//! * `routes/belief.rs` and `repos/divergence.rs` at origin/main, this file
//!   kept: the group-claim and attribution tests fail (WITHIN_FRAME missing;
//!   writer NULL on every edge); the read-refused control passes.
//! * only the first edge commit applied: both fail at SCOPED_BY.
//! * the edge SAVEPOINT removed (a refused GENERATED_BY aborts the stamped
//!   transaction): the group-claim, attribution and agent tests fail, the BBA
//!   having been rolled back with it.
//! * step 20's stamped transaction never opened: the group-claim test fails at
//!   the perspective-scoped belief.
//! * before the two `security(api)` commits: the agent test gets 201 and H's
//!   BBA overwritten; the foreign perspective gets 201; the own perspective's
//!   belief stays 0.8.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::belief::{submit_evidence, SubmitEvidenceRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    as_role, database_url_for, downgraded_pool, seed_agent_with_group, seed_human_operator,
};

const WORLD: Uuid = Uuid::nil();

/// Both pools on the application role, as in production.
async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

struct World {
    pool: PgPool,
    state: AppState,
    /// The human operator H, the claims' author.
    human: Uuid,
    /// The human operator H's group, where its agent's writes belong.
    hg: Uuid,
    /// An agent live-linked to H.
    agent: Uuid,
    /// An agent linked to no human, with its own personal group.
    stranger: Uuid,
    stranger_group: Uuid,
}

async fn armed_world(pool: PgPool) -> World {
    let (h, hg) = seed_human_operator(&pool, "fb9-human").await;
    let (agent, agent_group) = seed_agent_with_group(&pool, "fb9-agent").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "fb9-stranger").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, agent, h)
            .await
            .expect("agent -> H");
    }
    let armed: bool = as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let armed: bool =
            sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
                .fetch_one(&mut *conn)
                .await
                .expect("arm");
        (conn, armed)
    })
    .await;
    assert!(armed, "PREMISE: the database arms");
    assert_ne!(
        agent_group, hg,
        "PREMISE: the agent's own personal group is not H's, so landing in HG is the binding's \
         doing"
    );
    let state = app_role_state(&pool).await;
    World {
        pool,
        state,
        human: h,
        hg,
        agent,
        stranger,
        stranger_group,
    }
}

struct Target {
    claim: Uuid,
    frame: Uuid,
    perspective: Uuid,
    context: Uuid,
}

/// A claim authored by H in HG with `visibility`, a frame (not binary_truth),
/// a perspective, and a context whose `filter` modifier applies on that frame
/// (no `keep_indices`: it keeps the whole frame, so the masses are unchanged).
async fn target(w: &World, visibility: &str) -> Target {
    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    let author = w.human;
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, visibility, \
                             owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6)",
    )
    .bind(claim)
    .bind(format!("fb9 {visibility} claim {claim}"))
    .bind(hash)
    .bind(author)
    .bind(visibility)
    .bind(w.hg)
    .execute(&w.pool)
    .await
    .expect("seed claim");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) \
         RETURNING id",
    )
    .bind(format!("fb9-{}", Uuid::new_v4()))
    .fetch_one(&w.pool)
    .await
    .expect("seed frame");
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("fb9-p-{}", Uuid::new_v4()))
    .bind(author)
    .fetch_one(&w.pool)
    .await
    .expect("seed perspective");
    let context: Uuid = sqlx::query_scalar(
        "INSERT INTO contexts (name, context_type, applicable_frame_ids, modifier_type) \
         VALUES ($1, 'temporal', ARRAY[$2]::uuid[], 'filter') RETURNING id",
    )
    .bind(format!("fb9-c-{}", Uuid::new_v4()))
    .bind(frame)
    .fetch_one(&w.pool)
    .await
    .expect("seed context");
    Target {
        claim,
        frame,
        perspective,
        context,
    }
}

/// `caller` submits `{0: 0.8, Θ: 0.2}` on the target, naming itself and the
/// target's perspective.
async fn submit(w: &World, t: &Target, caller: Uuid) -> Result<Value, ApiError> {
    let body = serde_json::json!({
        "claim_id": t.claim, "agent_id": caller, "reliability": 1.0,
        "perspective_id": t.perspective,
        "masses": {"0": 0.8, "0,1": 0.2},
    });
    submit_body(w, t.frame, caller, body).await
}

/// `caller` (the authenticated principal) posts `body` on `frame`.
async fn submit_body(w: &World, frame: Uuid, caller: Uuid, body: Value) -> Result<Value, ApiError> {
    let request: SubmitEvidenceRequest = serde_json::from_value(body).expect("request");
    let viewer = Viewer::resolve(&w.pool, caller).await.expect("viewer");
    submit_evidence(
        ViewerExtractor(viewer),
        State(w.state.clone()),
        Path(frame),
        Json(request),
    )
    .await
    .map(|(status, body)| {
        assert_eq!(status.as_u16(), 201, "a stored submission is 201");
        serde_json::to_value(&body.0).expect("response json")
    })
}

#[derive(Debug, PartialEq)]
struct EdgeRow {
    relationship: String,
    owner: Uuid,
    writer: Option<Uuid>,
}

/// Every edge touching the target's nodes, read as the harness superuser.
async fn edges(w: &World, t: &Target) -> Vec<EdgeRow> {
    let rows: Vec<(String, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT relationship, owner_group_id, writer_group_id FROM edges \
          WHERE source_id = ANY($1) OR target_id = ANY($1) \
          ORDER BY relationship",
    )
    .bind(vec![t.claim, t.frame, t.perspective, t.context])
    .fetch_all(&w.pool)
    .await
    .expect("read edges");
    rows.into_iter()
        .map(|(relationship, owner, writer)| EdgeRow {
            relationship,
            owner,
            writer,
        })
        .collect()
}

fn the_one<'a>(rows: &'a [EdgeRow], relationship: &str) -> &'a EdgeRow {
    let found: Vec<&EdgeRow> = rows
        .iter()
        .filter(|r| r.relationship == relationship)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one {relationship} edge expected, got {rows:?}"
    );
    found[0]
}

/// The perspective-scoped belief row's owner, if one exists.
async fn perspective_belief_owner(w: &World, t: &Target) -> Option<Uuid> {
    sqlx::query_scalar(
        "SELECT owner_group_id FROM ds_combined_beliefs \
          WHERE frame_id = $1 AND claim_id = $2 AND scope_type = 'perspective' \
            AND scope_id = $3",
    )
    .bind(t.frame)
    .bind(t.claim)
    .bind(t.perspective)
    .fetch_optional(&w.pool)
    .await
    .expect("read ds_combined_beliefs")
}

/// The owners of the divergence records for (claim, frame).
async fn divergence_owners(w: &World, t: &Target) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT owner_group_id FROM ds_bayesian_divergence WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(t.claim)
    .bind(t.frame)
    .fetch_all(&w.pool)
    .await
    .expect("read ds_bayesian_divergence")
}

async fn bba_count(w: &World, t: &Target) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2")
        .bind(t.claim)
        .bind(t.frame)
        .fetch_one(&w.pool)
        .await
        .expect("read mass_functions")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_group_claims_edges_and_derived_rows_land_in_the_operators_group(pool: PgPool) {
    let w = armed_world(pool).await;
    let t = target(&w, "group").await;

    let resp = submit(&w, &t, w.agent)
        .await
        .expect("H's agent may submit on H's group claim");
    assert!(resp["mass_function_id"].is_string(), "{resp}");

    let rows = edges(&w, &t).await;
    for relationship in ["WITHIN_FRAME", "SCOPED_BY", "CONTRIBUTES_TO"] {
        assert_eq!(
            the_one(&rows, relationship),
            &EdgeRow {
                relationship: relationship.to_string(),
                owner: w.hg,
                writer: Some(w.hg),
            },
            "{relationship}: owned by H's group and written by it"
        );
    }
    assert!(
        rows.iter().all(|r| r.owner != WORLD),
        "a group claim's submission must leave no world-owned edge: {rows:?}"
    );
    assert_eq!(
        perspective_belief_owner(&w, &t).await,
        Some(w.hg),
        "the perspective-scoped belief lands in H's group"
    );
    assert_eq!(
        divergence_owners(&w, &t).await,
        vec![w.hg],
        "one divergence record, in H's group"
    );

    // Again on the same (claim, frame), by H itself (another source agent, so
    // a second BBA rather than an update of the first). Each submission's
    // GENERATED_BY INSERT (BBA -> agent) is refused on the stamped transaction;
    // under its savepoint that refusal must not abort the transaction, so the
    // BBA and every later write still commit.
    assert!(
        rows.iter().all(|r| r.relationship != "GENERATED_BY"),
        "PREMISE: a BBA -> agent GENERATED_BY edge is refused \
         (`trigger_validate_edge_refs`: a mass function is not an `evidence` row), which is \
         the refusal this case leans on to exercise the savepoint: {rows:?}"
    );
    submit(&w, &t, w.human)
        .await
        .expect("a second submission is stored");
    assert_eq!(bba_count(&w, &t).await, 2, "both BBAs persisted");
    let rows = edges(&w, &t).await;
    assert!(
        rows.iter()
            .all(|r| r.owner == w.hg && r.writer == Some(w.hg)),
        "every edge of both submissions is H's group's, written by it: {rows:?}"
    );
    assert_eq!(
        divergence_owners(&w, &t).await,
        vec![w.hg, w.hg],
        "each submission records its divergence, in H's group"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn attribution_follows_the_caller_not_the_claims_owner(pool: PgPool) {
    let w = armed_world(pool).await;
    let t = target(&w, "public").await;

    submit(&w, &t, w.stranger)
        .await
        .expect("anyone may submit evidence on a public claim");

    let rows = edges(&w, &t).await;
    for relationship in ["WITHIN_FRAME", "SCOPED_BY", "CONTRIBUTES_TO"] {
        assert_eq!(
            the_one(&rows, relationship).writer,
            Some(w.stranger_group),
            "{relationship}: the writer is the caller's group, not H's and not none: {rows:?}"
        );
    }
    // The derived rows, refused on the raw pool, now land too, for the claim's
    // operator. (The stranger's own derived-row writes are the derived tables'
    // row security's call, not this handler's, so they are not asserted.)
    submit(&w, &t, w.human)
        .await
        .expect("H submits on its own public claim");
    assert!(
        perspective_belief_owner(&w, &t).await.is_some(),
        "the perspective-scoped belief lands on a public claim"
    );
    assert!(
        !divergence_owners(&w, &t).await.is_empty(),
        "a divergence record lands on a public claim"
    );
}

/// A public community holding the target's perspective, seeded as the
/// harness superuser. Its membership row inherits the community's tenancy.
async fn community_of(w: &World, perspective: Uuid) -> Uuid {
    let community: Uuid = sqlx::query_scalar(
        "INSERT INTO communities (name, visibility, owner_group_id) \
         VALUES ($1, 'public', $2) RETURNING id",
    )
    .bind(format!("fb9-community-{}", Uuid::new_v4()))
    .bind(WORLD)
    .fetch_one(&w.pool)
    .await
    .expect("seed community");
    sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
        .bind(community)
        .bind(perspective)
        .execute(&w.pool)
        .await
        .expect("seed community membership");
    community
}

/// Step 17's community scope: the member perspectives' BBAs on a GROUP claim
/// are read as the caller (on the raw pool they are invisible, so no community
/// belief is computed), and the community-scoped belief is written on the
/// stamped transaction, in H's group. The community and its membership are
/// public, so only the BBA read and the write are under test here.
#[sqlx::test(migrations = "../../migrations")]
async fn a_community_scoped_belief_lands_in_the_operators_group(pool: PgPool) {
    let w = armed_world(pool).await;
    let t = target(&w, "group").await;
    let community = community_of(&w, t.perspective).await;

    submit(&w, &t, w.agent)
        .await
        .expect("H's agent may submit on H's group claim");

    let scoped = |scope_type: &'static str, scope_id: Uuid| {
        let pool = w.pool.clone();
        let (frame, claim) = (t.frame, t.claim);
        async move {
            sqlx::query_as::<_, (Uuid, f64)>(
                "SELECT owner_group_id, belief FROM ds_combined_beliefs \
                  WHERE frame_id = $1 AND claim_id = $2 AND scope_type = $3 \
                    AND scope_id = $4",
            )
            .bind(frame)
            .bind(claim)
            .bind(scope_type)
            .bind(scope_id)
            .fetch_all(&pool)
            .await
            .expect("read ds_combined_beliefs")
        }
    };
    let rows = scoped("community", community).await;
    assert_eq!(rows.len(), 1, "one community-scoped belief: {rows:?}");
    assert_eq!(
        rows[0].0, w.hg,
        "the community-scoped belief is H's group's"
    );
    // The community's one member perspective holds the one BBA, so the
    // community belief is that perspective's belief.
    let perspective = scoped("perspective", t.perspective).await;
    assert_eq!(perspective.len(), 1, "{perspective:?}");
    assert!(
        (rows[0].1 - perspective[0].1).abs() < 1e-9,
        "one member BBA: the community belief equals its perspective's, {} vs {}",
        rows[0].1,
        perspective[0].1
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_who_cannot_read_the_claim_writes_nothing(pool: PgPool) {
    let w = armed_world(pool).await;
    let t = target(&w, "group").await;

    let refused = submit(&w, &t, w.stranger).await;
    assert!(
        matches!(refused, Err(ApiError::NotFound { .. })),
        "an unreadable claim is a 404: {refused:?}"
    );
    assert_eq!(edges(&w, &t).await, vec![], "no edge written");
    assert_eq!(bba_count(&w, &t).await, 0, "no BBA written");
    assert_eq!(perspective_belief_owner(&w, &t).await, None);
    assert_eq!(divergence_owners(&w, &t).await, Vec::<Uuid>::new());
}

/// The masses of `agent`'s BBA on (claim, frame), if it has one.
async fn bba_of(w: &World, t: &Target, agent: Uuid) -> Option<Value> {
    sqlx::query_scalar(
        "SELECT masses FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id = $3",
    )
    .bind(t.claim)
    .bind(t.frame)
    .bind(agent)
    .fetch_optional(&w.pool)
    .await
    .expect("read mass_functions")
}

/// The body's `agent_id` is the BBA's author and half its upsert key
/// `(claim, frame, source_agent_id, perspective)`. A caller may name only
/// itself: naming another agent is refused (403) before anything is written,
/// so it can neither attribute evidence to that agent nor overwrite that
/// agent's BBA. W is a token-capable agent (linked to no human) holding a
/// writer membership in HG, so row security alone would let it update H's
/// HG-owned row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_cannot_submit_as_another_agent(pool: PgPool) {
    let w = armed_world(pool).await;
    let t = target(&w, "public").await;
    let (writer, _) = seed_agent_with_group(&w.pool, "fb9-writer").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(w.hg)
    .bind(writer)
    .execute(&w.pool)
    .await
    .expect("a writer membership in HG");

    let mine = serde_json::json!({
        "claim_id": t.claim, "agent_id": w.human, "reliability": 1.0,
        "masses": {"0": 0.6, "0,1": 0.4},
    });
    submit_body(&w, t.frame, w.human, mine)
        .await
        .expect("H submits as itself");
    let before = bba_of(&w, &t, w.human).await.expect("H's BBA");

    let spoofed = serde_json::json!({
        "claim_id": t.claim, "agent_id": w.human, "reliability": 1.0,
        "masses": {"0": 0.1, "1": 0.9},
    });
    let refused = submit_body(&w, t.frame, writer, spoofed).await;
    assert!(
        matches!(refused, Err(ApiError::Forbidden { .. })),
        "W naming H as the author must be 403: {refused:?}"
    );
    assert_eq!(
        bba_of(&w, &t, w.human).await,
        Some(before),
        "H's BBA is untouched"
    );
    assert_eq!(bba_count(&w, &t).await, 1, "no BBA was added");
    assert_eq!(bba_of(&w, &t, writer).await, None);

    // Control: W naming itself is stored.
    let own = serde_json::json!({
        "claim_id": t.claim, "agent_id": writer, "reliability": 1.0,
        "masses": {"0": 0.5, "0,1": 0.5},
    });
    submit_body(&w, t.frame, writer, own)
        .await
        .expect("W submits as itself");
    assert!(bba_of(&w, &t, writer).await.is_some(), "W's own BBA landed");
    assert_eq!(bba_count(&w, &t).await, 2);
}

/// Every BBA has an author (operator ruling 2026-10-22: "Evidence shouldn't
/// be able to have no agent_id"). An omitted `agent_id` is the caller's own,
/// so it lands in the caller's slot. Before, every agent-less submission on
/// one (claim, frame, perspective) shared ONE row under the `NULLS NOT
/// DISTINCT` key, and a second caller's agent-less submission replaced the
/// first's (backlog 5a3ba157).
#[sqlx::test(migrations = "../../migrations")]
async fn an_omitted_agent_id_is_the_callers_own(pool: PgPool) {
    let w = armed_world(pool).await;
    let t = target(&w, "public").await;
    let (writer, _) = seed_agent_with_group(&w.pool, "fb9-writer").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(w.hg)
    .bind(writer)
    .execute(&w.pool)
    .await
    .expect("a writer membership in HG");

    let h_body = serde_json::json!({
        "claim_id": t.claim, "reliability": 1.0,
        "masses": {"0": 0.6, "0,1": 0.4},
    });
    submit_body(&w, t.frame, w.human, h_body)
        .await
        .expect("H submits with no agent_id");
    let h_bba = bba_of(&w, &t, w.human)
        .await
        .expect("H's omitted agent_id is H's own: the BBA is authored by H");

    let w_body = serde_json::json!({
        "claim_id": t.claim, "reliability": 1.0,
        "masses": {"0": 0.1, "1": 0.9},
    });
    submit_body(&w, t.frame, writer, w_body)
        .await
        .expect("W submits with no agent_id");

    assert_eq!(
        bba_of(&w, &t, w.human).await,
        Some(h_bba),
        "W's agent-less submission must not replace H's BBA"
    );
    assert!(
        bba_of(&w, &t, writer).await.is_some(),
        "W's omitted agent_id is W's own"
    );
    let authorless: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id IS NULL",
    )
    .bind(t.claim)
    .bind(t.frame)
    .fetch_one(&w.pool)
    .await
    .expect("read mass_functions");
    assert_eq!(authorless, 0, "no BBA is stored without an author");
    assert_eq!(bba_count(&w, &t).await, 2, "two authors, two BBAs");
}

/// A perspective seeded `visibility = 'group'` in `group`, with
/// `confidence_calibration`.
async fn private_perspective(w: &World, group: Uuid, author: Uuid, calibration: f64) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id, visibility, owner_group_id, \
                                   confidence_calibration) \
         VALUES ($1, $2, 'group', $3, $4) RETURNING id",
    )
    .bind(format!("fb9-private-p-{}", Uuid::new_v4()))
    .bind(author)
    .bind(group)
    .bind(calibration)
    .fetch_one(&w.pool)
    .await
    .expect("seed a private perspective")
}

/// A `perspective_id` the caller cannot read is a 404 before anything is
/// written. It used to be looked up on the raw pool and, when that lookup
/// found nothing, the submission went ahead: the BBA was filed under the other
/// group's perspective (the foreign key does not see row security), its
/// CONTRIBUTES_TO edge and perspective-scoped belief were written, and the
/// perspective's calibration discount was skipped.
#[sqlx::test(migrations = "../../migrations")]
async fn a_perspective_the_caller_cannot_read_is_refused(pool: PgPool) {
    let w = armed_world(pool).await;
    let t = target(&w, "public").await;
    let foreign = private_perspective(&w, w.stranger_group, w.stranger, 0.5).await;

    let body = serde_json::json!({
        "claim_id": t.claim, "agent_id": w.human, "reliability": 1.0,
        "perspective_id": foreign,
        "masses": {"0": 0.8, "0,1": 0.2},
    });
    let refused = submit_body(&w, t.frame, w.human, body).await;
    assert!(
        matches!(refused, Err(ApiError::NotFound { ref entity, .. }) if entity == "perspective"),
        "another group's private perspective must be a 404: {refused:?}"
    );
    assert_eq!(bba_count(&w, &t).await, 0, "no BBA written");
    let contributes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'CONTRIBUTES_TO'",
    )
    .bind(foreign)
    .fetch_one(&w.pool)
    .await
    .expect("read edges");
    assert_eq!(
        contributes, 0,
        "no CONTRIBUTES_TO from the foreign perspective"
    );
    let scoped: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ds_combined_beliefs WHERE scope_type = 'perspective' \
           AND scope_id = $1",
    )
    .bind(foreign)
    .fetch_one(&w.pool)
    .await
    .expect("read ds_combined_beliefs");
    assert_eq!(scoped, 0, "no belief scoped to the foreign perspective");
}

/// The other half of the same lookup: the caller's OWN group-private
/// perspective is read as the caller, so its confidence calibration applies.
/// On the raw pool that read saw no group row, and the discount was silently
/// skipped. `{0: 0.8, Θ: 0.2}` discounted at 0.5 is `{0: 0.4, Θ: 0.6}`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_callers_own_private_perspective_calibrates_its_evidence(pool: PgPool) {
    let w = armed_world(pool).await;
    let t = target(&w, "group").await;
    let own = private_perspective(&w, w.hg, w.human, 0.5).await;

    let body = serde_json::json!({
        "claim_id": t.claim, "agent_id": w.human, "reliability": 1.0,
        "perspective_id": own,
        "masses": {"0": 0.8, "0,1": 0.2},
    });
    let resp = submit_body(&w, t.frame, w.human, body)
        .await
        .expect("H submits under its own perspective");
    let belief = resp["updated_belief"].as_f64().expect("updated_belief");
    assert!(
        (belief - 0.4).abs() < 1e-9,
        "the perspective's 0.5 calibration must discount m({{0}}) 0.8 to 0.4, got {belief}: \
         {resp}"
    );
}
