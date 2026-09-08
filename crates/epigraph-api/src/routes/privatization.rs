//! D4 admin privatization — plan creation (which IS the preview) and the
//! read surface over persisted plans.
//!
//! All under `/api/v1/admin/privatization`, in the **`protected`** router. Every
//! statement this module runs lives in
//! `epigraph_db::repos::privatization` — there is no SQL here, per CLAUDE.md and
//! FINAL-PLAN §6.5.1 ("All selection SQL lives in `repos/privatization.rs`. No
//! SQL in routes or MCP tools").
//!
//! # `POST /plans` IS the dry run
//!
//! There is no `?dry_run=true`. Creating a plan runs the selection, freezes it,
//! and returns the whole preview with `201`. FINAL-PLAN §6.5.1 forbids a
//! stateless preview: the id set is frozen into `privatization_plan_items` and a
//! later `apply` operates on that frozen set, not on a re-evaluated selector.
//!
//! # THREE CONNECTIONS, THREE AUTHORITIES, IN ONE REQUEST
//!
//! This is the part that goes wrong quietly, so it is written out. FINAL-PLAN
//! §6.5.2 records a previous revision of this design that shipped a cross-tenant
//! read oracle, and every one of the three closures below is a connection
//! choice:
//!
//! 1. **Authorization** — the MAINTENANCE connection.
//!    `require_instance_admin_for_group` counts the target group's other live
//!    admins, and on a stamped app connection migration 077's policy narrows
//!    `group_memberships` to what the caller can see, so the count under-reports
//!    and an authorised operator is refused. See that function's own doc.
//! 2. **Selection and the freeze** — the MAINTENANCE connection, under a BYPASS
//!    viewer minted with `SystemReason::PrivatizationSelection`. Selection MUST
//!    be unfiltered: one narrowed to what the actor can see would silently omit
//!    the rows privatization exists to catch and report success. `EXECUTE` on
//!    migration 080's two selection functions is granted to
//!    `epigraph_maintenance` alone, so this is forced rather than chosen.
//! 3. **Rendering, and every read of a persisted plan** — a STAMPED APP
//!    connection under the ACTOR's own `Viewer`. Ids and content are filtered;
//!    counts are not. On the maintenance connection `epigraph_bypass()` is true,
//!    migration 087's policies admit every row, and these reads become the
//!    oracle. A `get_plan` that reused the maintenance connection already in
//!    hand would pass every test.
//!
//! **Counts are not re-filtered; ids and content are.** Getting that backwards
//! produces either a wrong plan (filtering selection) or the oracle (filtering
//! nothing).
//!
//! # Every READ endpoint carries the same check as `POST /plans`
//!
//! FINAL-PLAN §6.5.2 point 2: the previous revision required `instance:admin`
//! **plus** group-admin-in-target to CREATE a plan and only `instance:admin` to
//! READ one, so any instance admin could read any other admin's preview and the
//! complete entity-id list of their private region. Here the check is in TWO
//! places and both are load-bearing:
//!
//! * the handler calls `require_instance_admin_for_group` before it answers, so
//!   the refusal is a 403 with a reason; and
//! * migration 087's SELECT policies narrow both plan tables to plans whose
//!   target group the connection's principal administers, so a handler that
//!   FORGOT the call would return an empty result rather than another admin's
//!   plan.
//!
//! The policy is the control; the handler call is the diagnosis.
//!
//! # `not_visible_to_actor` is a COUNT, with no ids and no content
//!
//! An item the actor cannot read contributes to `counts.not_visible_to_actor`
//! and to nothing else — never a placeholder, never a redaction sentinel, never
//! an id. `sample`, `boundary_edges.sample` and the `items` list are all
//! rendered under the actor's viewer.
//!
//! **THE PAGINATION TOKEN IS PART OF THAT RULE, IN BOTH DIRECTIONS.** The page
//! cursor is a POSITION in the frozen set's total order: the handler never
//! serialises an entity id into `next_cursor`, and it never accepts an ordering
//! key chosen by the caller. A response field and a query parameter are the
//! same surface as `sample` for this purpose, and an id that may only be
//! counted may not appear in either. `PrivatizationRepository::load_plan_items_conn`
//! carries the argument for why an offset is sound over this particular table.
//!
//! # What this module does NOT do, and why
//!
//! `approve`, `apply`, `abort`, `revert`, the seal/unseal manifest ceremony and
//! `GET /audit` are absent. Approving a plan is an UPDATE of
//! `privatization_plans`, and that table has no UPDATE policy: migration 087
//! covers SELECT and INSERT only, `rls_enforcement.rs::DELIBERATELY_UNCOVERED`
//! assigns the UPDATE pair to the apply/revert slice, and under `FORCE` an
//! uncovered command is denied to every role including a bypass connection. So
//! FINAL-PLAN's PR-18 acceptance clauses 3 and 4 — `approve` by `created_by`,
//! and `approve` by an instance admin who does not administer the target group,
//! both 409 — are NOT discharged here. The database halves of both exist (080's
//! `pp_four_eyes` CHECK and 081's `epigraph_privatization_approver_guard`);
//! their HTTP halves need the UPDATE policy first.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{errors::ApiError, state::AppState};

// =============================================================================
// REQUEST TYPES
// =============================================================================

/// `POST /api/v1/admin/privatization/plans` body.
#[derive(Deserialize, Debug, Clone)]
pub struct CreatePlanRequest {
    /// `restrict` (default) or `seal`.
    #[serde(default)]
    pub mode: Option<String>,
    /// The group the plan would move its items into.
    pub target_group_id: Uuid,
    /// Exactly one of `ids`, `predicate`, `saved_query`.
    pub seeds: PlanSeeds,
    /// Closure traversal parameters.
    #[serde(default)]
    pub closure: Option<ClosureBody>,
    /// `abort` (default) | `skip` | `reassign`.
    #[serde(default)]
    pub on_conflict: Option<String>,
    /// Seal-mode plaintext padding bucket: 0, 256, 1024 or 4096.
    #[serde(default)]
    pub pad_to: Option<i32>,
}

/// The three selector arms of FINAL-PLAN §6.5.1.
#[derive(Deserialize, Debug, Clone)]
pub struct PlanSeeds {
    /// "These seventeen specific claims" — what incident response looks like.
    #[serde(default)]
    pub ids: Option<SeedIds>,
    /// A re-runnable selector. See [`SeedPredicate`] for the subset served.
    #[serde(default)]
    pub predicate: Option<SeedPredicate>,
    /// Schema slot only; `501`.
    #[serde(default)]
    pub saved_query: Option<serde_json::Value>,
}

/// The `ids` arm.
#[derive(Deserialize, Debug, Clone)]
pub struct SeedIds {
    /// Claim ids.
    pub claims: Vec<Uuid>,
}

/// The `predicate` arm.
///
/// FINAL-PLAN §6.5.1 says this arm "reuses `ClaimRepository::list_by_labels`
/// verbatim", and it does. That repository method expresses `labels`,
/// `exclude_labels` and `current_only`; the plan's sketch also names
/// `agent_id`, `properties_contains` and `created_before`, which it does not.
/// Those three are accepted by the deserializer and REFUSED with a 400 naming
/// them, rather than silently ignored — a selector that quietly drops a
/// narrowing clause selects MORE than the operator asked for, which is the
/// direction that matters here.
#[derive(Deserialize, Debug, Clone)]
pub struct SeedPredicate {
    /// Claims carrying all of these labels.
    #[serde(default)]
    pub labels: Vec<String>,
    /// Claims carrying none of these labels.
    #[serde(default)]
    pub exclude_labels: Vec<String>,
    /// Restrict to `is_current` claims. Defaults to true.
    #[serde(default)]
    pub current_only: Option<bool>,
    /// Not served by this build; a value here is a 400.
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    /// Not served by this build; a value here is a 400.
    #[serde(default)]
    pub properties_contains: Option<serde_json::Value>,
    /// Not served by this build; a value here is a 400.
    #[serde(default)]
    pub created_before: Option<chrono::DateTime<chrono::Utc>>,
}

/// The `closure` block.
#[derive(Deserialize, Debug, Clone)]
pub struct ClosureBody {
    /// Relationships to traverse; case-insensitive. Structural types are
    /// refused.
    #[serde(default)]
    pub edge_types: Option<Vec<String>>,
    /// `out` | `in` | `both`.
    #[serde(default)]
    pub direction: Option<String>,
    /// Hops from a seed. Ceiling: `MAX_TRAVERSAL_DEPTH`.
    #[serde(default)]
    pub max_depth: Option<i32>,
    /// Total nodes. Ceiling: `MAX_NODE_CAP`.
    #[serde(default)]
    pub node_cap: Option<i32>,
}

/// `GET /api/v1/admin/privatization/plans` query.
#[derive(Deserialize, Debug, Default)]
pub struct PlanListQuery {
    /// Filter by plan state.
    pub state: Option<String>,
    /// Filter by target group.
    pub target_group_id: Option<Uuid>,
    /// Page size, clamped to `MAX_PAGE`.
    pub limit: Option<i64>,
}

/// `GET /api/v1/admin/privatization/plans/:id/items` query.
///
/// §6.5.7 also lists `state`, `kind` and `depth` filters on this row; this build
/// serves `limit` and `cursor` only, and the divergence is recorded in
/// `docs/tenancy/progress.json` under `plan_corrections`.
#[derive(Deserialize, Debug, Default)]
pub struct PlanItemQuery {
    /// Page size, clamped to `MAX_PAGE`.
    pub limit: Option<i64>,
    /// Opaque cursor from a previous page's `next_cursor`. A POSITION in the
    /// frozen set's total order, never an entity id — see `parse_cursor`.
    pub cursor: Option<String>,
}

// =============================================================================
// RESPONSE TYPES
// =============================================================================

/// The `201` body of `POST /plans`.
///
/// **A SUBSET of FINAL-PLAN §6.5.2's response schema.** The fields the PR-18
/// acceptance clause names are all here; the remainder is owned by the
/// apply/revert slice and by PR-21, and the omission is recorded in
/// `docs/tenancy/progress.json` under `plan_corrections` rather than left to be
/// discovered by diffing this struct against the plan. `GET /plans/:id` serves
/// [`PlanSummary`], not this type and not §6.5.7's "preview + live progress".
#[derive(Serialize, Debug)]
pub struct PlanPreview {
    /// The persisted plan's id.
    pub plan_id: Uuid,
    /// Plan state, from `privatization_plans.state`.
    pub state: String,
    /// `restrict` or `seal`.
    pub mode: String,
    /// The group the plan would move its items into.
    pub target_group_id: Uuid,
    /// BLAKE3 over the frozen `(kind, entity_id)` set, `b3:` + hex. An apply
    /// must echo it.
    pub plan_digest: String,
    /// DERIVED, not stored: `created_at + 4h`. Migration 080 has no column for
    /// it and is applied and frozen, so the field is computed here and labelled
    /// as computed rather than invented as schema.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// The counts block.
    pub counts: PreviewCounts,
    /// Up to 25 items the ACTOR can read.
    pub sample: Vec<SampleItem>,
    /// The boundary survey.
    pub boundary_edges: BoundaryEdges,
    /// Operator-facing warnings.
    pub warnings: Vec<String>,
    /// `item_count > 1000 OR authors_losing_count > 0`.
    pub requires_second_approver: bool,
}

/// `counts` in the preview.
#[derive(Serialize, Debug)]
pub struct PreviewCounts {
    /// How many seeds the selector resolved to.
    pub seeds: usize,
    /// How many entities the mandatory content-lineage hull contributed.
    pub hull: usize,
    /// The frozen set's cardinality.
    pub total: usize,
    /// How many item rows were actually written. **Always equal to `total` in a
    /// `201`**: a shortfall — an id that stopped naming a live claim between
    /// selection and the freeze — rolls the whole plan back with a `409`,
    /// because the persisted `plan_digest` is computed over `total` and no
    /// UPDATE policy exists to correct it afterwards. Serialised anyway so the
    /// invariant is visible on the wire rather than only asserted in a test.
    pub frozen: u64,
    /// Distinct authors who would lose access to their own claims.
    ///
    /// **A SCALAR, where FINAL-PLAN §6.5.2 specifies an array under
    /// `reachability_delta` carrying a per-author `member_of_target` flag.** The
    /// PR-18 acceptance line's words ("reports `authors_losing_own_claims`") are
    /// satisfied by the count, and the count is what drives
    /// `requires_second_approver`; the per-author breakdown needs a repo
    /// primitive that does not exist and is owned by a later slice. Recorded in
    /// `docs/tenancy/progress.json` under `plan_corrections`.
    pub authors_losing_own_claims: i64,
    /// **A COUNT, with no ids and no content** (sec F7).
    pub not_visible_to_actor: i64,
    /// `depth -> count`.
    pub by_depth: std::collections::BTreeMap<i32, i64>,
}

/// One rendered sample item. Present ONLY because the actor can read it.
#[derive(Serialize, Debug)]
pub struct SampleItem {
    /// The claim id.
    pub id: Uuid,
    /// A short prefix of `content`.
    pub preview: String,
}

/// The boundary survey.
#[derive(Serialize, Debug)]
pub struct BoundaryEdges {
    /// **NOT named `total`.** FINAL-PLAN §6.5.2's schema calls this field
    /// `total`; the computation behind it restricts to
    /// `source_type='claim' AND target_type='claim'`, so an edge from a selected
    /// claim's evidence to an entity outside the selection is a genuine
    /// straddling boundary this number does not count. Serialising a subtotal as
    /// `total` is the drift the name refuses.
    pub claim_to_claim: i64,
    /// Boundary edge counts keyed by relationship.
    pub by_relationship: std::collections::BTreeMap<String, i64>,
    /// Boundary edge ids the ACTOR can read.
    pub sample: Vec<Uuid>,
}

/// `GET /plans` body.
#[derive(Serialize, Debug)]
pub struct PlanListResponse {
    /// Plans whose target group the caller administers.
    pub plans: Vec<PlanSummary>,
}

/// One row of `GET /plans`.
#[derive(Serialize, Debug)]
pub struct PlanSummary {
    /// The plan's id.
    pub plan_id: Uuid,
    /// Plan state.
    pub state: String,
    /// `restrict` or `seal`.
    pub mode: String,
    /// The group the plan would move its items into.
    pub target_group_id: Uuid,
    /// The frozen set's cardinality.
    pub item_count: i32,
    /// Distinct authors who would lose access to their own claims.
    pub authors_losing_count: i32,
    /// When the plan was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Derived: `created_at + 4h`.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /plans/:id/items` body.
#[derive(Serialize, Debug)]
pub struct PlanItemsResponse {
    /// Items the actor can read, with a content preview.
    pub items: Vec<PlanItem>,
    /// **A COUNT** of items on this page the actor cannot read (sec F7).
    pub not_visible_to_actor: i64,
    /// Cursor for the next page, or `null`. A POSITION in the frozen set's
    /// total order; it carries no entity id, so it is emitted whatever the last
    /// row on the page happened to be.
    pub next_cursor: Option<String>,
}

/// One rendered item of a plan's frozen set.
#[derive(Serialize, Debug)]
pub struct PlanItem {
    /// `claim` or `evidence`.
    pub kind: String,
    /// The entity id. Present ONLY because the actor can read it.
    pub id: Uuid,
    /// Hops from the nearest seed.
    pub depth: i32,
    /// `seed` | `closure:<rel>` | `hull:supersedes` | `hull:step_lineage`.
    pub via: Option<String>,
    /// Item state.
    pub state: String,
    /// A short prefix of `content`.
    pub preview: String,
}

// =============================================================================
// BOUNDS
// =============================================================================

/// The largest page any list endpoint here will return.
#[cfg(feature = "db")]
const MAX_PAGE: i64 = 500;

/// The default page size.
#[cfg(feature = "db")]
const DEFAULT_PAGE: i64 = 100;

/// How many items the preview's `sample` carries (FINAL-PLAN §6.5.2).
#[cfg(feature = "db")]
const SAMPLE_SIZE: usize = 25;

/// How many boundary edge ids the preview's `boundary_edges.sample` carries.
#[cfg(feature = "db")]
const BOUNDARY_SAMPLE: i64 = 25;

/// The preview TTL FINAL-PLAN §6.5.2 gives a plan. DERIVED from `created_at`;
/// migration 080 stores no `expires_at`.
#[cfg(feature = "db")]
const PLAN_TTL_HOURS: i64 = 4;

/// The bound acceptance clause 1 requires a preview to return within.
///
/// The maintenance pool carries no statement timeout of its own, and the closure
/// and the hull are the two statements in this system that can walk the whole
/// edge corpus — the hull being a LOOP of them. Applied to the connection by
/// `PrivatizationRepository::select` before the first statement.
///
/// # IT COVERS THOSE TWO STATEMENTS AND NOT THE WHOLE PREVIEW
///
/// `select` restores the connection's prior bound before it returns, so the
/// plan INSERT, the freeze and the actor-scoped rendering pass all run under
/// whatever the pool was built with. That is the right scope — the two
/// corpus-walking statements are what the bound exists for, and the alternative
/// is a session-scope `SET` left on a pooled connection for the next borrower —
/// but it means "the preview returns within this bound" is not literally true of
/// the whole handler, so it is written here rather than assumed.
#[cfg(feature = "db")]
const SELECTION_STATEMENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `requires_second_approver` threshold from FINAL-PLAN §6.5.2.
#[cfg(feature = "db")]
const SECOND_APPROVER_ITEM_THRESHOLD: usize = 1000;

// =============================================================================
// HANDLERS (db feature)
// =============================================================================

/// `POST /api/v1/admin/privatization/plans` — run the selection, freeze it,
/// return the preview.
///
/// # Errors
///
/// `401` no auth context; `403` any of FINAL-PLAN §6.6's four conditions;
/// `400` a refused selector — including §3.1's two request ceilings, which are
/// a refusal and not a truncation; `501` a `saved_query` seed or `mode=seal`;
/// `500` a database fault.
#[cfg(feature = "db")]
#[allow(clippy::too_many_lines)]
pub async fn create_plan(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(body): Json<CreatePlanRequest>,
) -> Result<(axum::http::StatusCode, Json<PlanPreview>), ApiError> {
    use epigraph_db::repos::privatization::{
        ClosureDirection, ClosureRequest, NewPlan, PrivatizationRepository, RESTATEMENT_EDGE_TYPES,
    };
    use epigraph_db::visibility::SystemReason;

    // An ABSENT auth context is a refusal, not a pass. This route is on the
    // `protected` chain, which layers a mandatory bearer middleware, so the
    // branch is unreachable today; it is written as a refusal anyway so the
    // handler's correctness does not depend on which chain it is registered on.
    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let mode = body.mode.as_deref().unwrap_or("restrict");
    if mode == "seal" {
        // FINAL-PLAN §6.5.6's seal is a two-phase, client-driven key ceremony
        // and `crates/epigraph-privacy` does not exist yet. A preview that
        // described a seal it cannot perform would be a promise.
        return Err(ApiError::NotImplemented {
            feature: "mode=seal; seal is a later slice and its side effects cannot be previewed \
                      honestly before the encryptor exists"
                .to_string(),
        });
    }
    if mode != "restrict" {
        return Err(ApiError::BadRequest {
            message: format!("mode must be 'restrict' or 'seal', got '{mode}'"),
        });
    }
    let on_conflict = body.on_conflict.as_deref().unwrap_or("abort");
    if !matches!(on_conflict, "abort" | "skip" | "reassign") {
        return Err(ApiError::BadRequest {
            message: format!("on_conflict must be abort|skip|reassign, got '{on_conflict}'"),
        });
    }
    let pad_to = body.pad_to.unwrap_or(256);
    if !matches!(pad_to, 0 | 256 | 1024 | 4096) {
        return Err(ApiError::BadRequest {
            message: format!("pad_to must be one of 0, 256, 1024, 4096, got {pad_to}"),
        });
    }

    // The selector, stored verbatim so a re-preview is reproducible.
    let selector = serde_json::json!({
        "seeds": {
            "ids": body.seeds.ids.as_ref().map(|s| &s.claims),
            "predicate": body.seeds.predicate.as_ref().map(|p| serde_json::json!({
                "labels": p.labels,
                "exclude_labels": p.exclude_labels,
                "current_only": p.current_only,
            })),
        },
        "closure": {
            "edge_types": body.closure.as_ref().and_then(|c| c.edge_types.clone()),
            "direction": body.closure.as_ref().and_then(|c| c.direction.clone()),
            "max_depth": body.closure.as_ref().and_then(|c| c.max_depth),
            "node_cap": body.closure.as_ref().and_then(|c| c.node_cap),
        },
        "mode": mode,
        "on_conflict": on_conflict,
        "pad_to": pad_to,
    });

    // ---- THE MAINTENANCE CONNECTION. Authorization, selection, freeze. ----
    let (mut maint, bypass) = state
        .maintenance_viewer(SystemReason::PrivatizationSelection)
        .await
        .map_err(|e| {
            tracing::error!(
                target: "tenancy.privatization",
                error = %e,
                handler = "create_plan",
                "could not acquire the maintenance connection"
            );
            ApiError::InternalError {
                message: "Failed to acquire a maintenance connection".to_string(),
            }
        })?;

    let actor = crate::middleware::instance_authz::require_instance_admin_for_group(
        auth,
        body.target_group_id,
        &mut maint,
    )
    .await?;

    // The closure bounds are resolved BEFORE the seeds, because `node_cap`
    // bounds the seed set too — see `resolve_seeds`.
    let closure = body.closure.clone().unwrap_or(ClosureBody {
        edge_types: None,
        direction: None,
        max_depth: None,
        node_cap: None,
    });
    let edge_types: Vec<String> = closure.edge_types.clone().unwrap_or_else(|| {
        RESTATEMENT_EDGE_TYPES
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    });
    let direction = match closure.direction.as_deref().unwrap_or("both") {
        "out" => ClosureDirection::Out,
        "in" => ClosureDirection::In,
        "both" => ClosureDirection::Both,
        other => {
            return Err(ApiError::BadRequest {
                message: format!("closure.direction must be out|in|both, got '{other}'"),
            })
        }
    };
    let node_cap = closure.node_cap.unwrap_or(10_000);

    // Seeds. Resolved on the maintenance connection under the bypass viewer,
    // for the same reason the closure is: a seed set narrowed to what the actor
    // can see is a plan that misses the rows it exists to find.
    let seeds = resolve_seeds(&mut maint, &bypass, &body.seeds, node_cap).await?;
    if seeds.is_empty() {
        return Err(ApiError::BadRequest {
            message: "the selector resolved to no seeds; a privatization needs at least one"
                .to_string(),
        });
    }

    let request = ClosureRequest {
        seeds: &seeds,
        edge_types: &edge_types,
        direction,
        max_depth: closure.max_depth.unwrap_or(3),
        node_cap,
    };

    let selection =
        PrivatizationRepository::select(&mut maint, &bypass, request, SELECTION_STATEMENT_TIMEOUT)
            .await
            .map_err(selection_error)?;

    let authors_losing = selection
        .authors_losing_own_claims(&mut maint, &bypass, body.target_group_id)
        .await?;
    let boundary_counts = selection.boundary_edge_counts(&mut maint, &bypass).await?;
    let omitted = selection
        .omitted_edge_types(&mut maint, &bypass, &edge_types)
        .await?;

    let digest = selection.digest();
    let item_count = i32::try_from(selection.item_count()).unwrap_or(i32::MAX);
    let authors_losing_count = i32::try_from(authors_losing).unwrap_or(i32::MAX);

    // ---- ONE TRANSACTION FOR THE PLAN ROW AND ITS FROZEN ITEMS ----
    //
    // These two statements are inseparable and the reason is structural rather
    // than tidiness. Migration 087 covers SELECT and INSERT on both plan tables
    // and nothing else, and under `FORCE` an uncovered command is denied to
    // every role including a bypass connection — so a plan row that was written
    // and then NOT populated could never afterwards be corrected or deleted by
    // anyone. Autocommitting them separately made that state reachable from any
    // failure between the two, and `SELECTION_STATEMENT_TIMEOUT` makes a large
    // but legal selection one of the ways to reach it.
    let mut tx = sqlx::Connection::begin(&mut *maint)
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;

    // The plan row is written COMPLETE — see `create_previewed_plan` for why it
    // cannot be inserted and then updated.
    let (plan_id, created_at) = PrivatizationRepository::create_previewed_plan(
        &mut tx,
        NewPlan {
            mode,
            target_group_id: body.target_group_id,
            selector: &selector,
            on_conflict,
            pad_to,
            created_by: actor,
            plan_digest: &digest,
            item_count,
            authors_losing_count,
        },
    )
    .await
    .map_err(plan_write_error)?;

    let frozen = selection.freeze_into(&mut tx, plan_id).await?;

    // THE PERSISTED DIGEST MUST DESCRIBE THE PERSISTED ITEMS.
    //
    // `plan_digest` and `item_count` are computed over the selection, before the
    // freeze, and they cannot be corrected afterwards — `privatization_plans`
    // has no UPDATE policy. `freeze_into`'s INNER JOIN to `claims` drops any id
    // that stopped naming a live claim in between, so a shortfall would persist
    // a digest of a set the plan does not contain, and PR-18c's apply is
    // chartered to validate exactly that digest against exactly that set. The
    // transaction is therefore rolled back and the operator asked to re-run,
    // rather than a permanently self-inconsistent row being written.
    //
    // WHY `item_count()` IS THE RIGHT QUANTITY TO COMPARE AGAINST, since the
    // three numbers involved are computed three different ways. `digest()`
    // hashes a set `plan_digest` DEDUPES; `freeze_into` carries `ON CONFLICT DO
    // NOTHING`, so its row count is the distinct-and-live cardinality; and
    // `item_count()` is a plain `len()`. They coincide because
    // `PrivatizationRepository::select` — the only constructor of an
    // `UnfilteredSelection` the request path can reach, which is what the
    // `locked_decisions.rs` source lint holds — returns
    // `select_content_lineage_hull`'s output, and that is built from a
    // `BTreeMap` keyed on `claim_id`. So the items are unique by construction,
    // every kind is `claim`, and the only way the three can disagree is the
    // dropped-claim race this branch catches. If a future change gives the
    // wrapper a second production constructor, that argument has to be redone.
    if frozen != u64::try_from(selection.item_count()).unwrap_or(u64::MAX) {
        return Err(ApiError::Conflict {
            reason:
                "the selection changed while the plan was being frozen; nothing was persisted. \
                     Re-run the preview"
                    .to_string(),
        });
    }
    tx.commit()
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;

    // ---- THE ACTOR'S OWN CONNECTION. Ids and content, and nothing wider. ----
    //
    // Acquired AFTER the freeze, and the maintenance connection is dropped
    // first: holding both while rendering is what makes it easy to render on
    // the wrong one.
    drop(maint);

    let mut read = state.read_as(&viewer).await.map_err(scoped_read_error)?;
    let visible = selection
        .visible_count(&mut read, &viewer)
        .await
        .map_err(selection_error)?;
    let sample = selection
        .render_previews(&mut read, &viewer, SAMPLE_SIZE)
        .await
        .map_err(selection_error)?;
    let boundary_sample = selection
        .render_boundary_edges(&mut read, &viewer, BOUNDARY_SAMPLE)
        .await
        .map_err(selection_error)?;
    read.commit().await.map_err(scoped_read_error)?;

    let mut warnings: Vec<String> = omitted
        .iter()
        .map(|w| {
            format!(
                "closure.edge_types omits '{}': {} claims are reachable in one hop along it and \
                 will remain as they are",
                w.relationship, w.would_add
            )
        })
        .collect();
    let not_visible = i64::try_from(selection.item_count()).unwrap_or(i64::MAX) - visible;
    if not_visible > 0 {
        warnings.push(format!(
            "{not_visible} selected items are not visible to you; they are counted but not \
             enumerated"
        ));
    }
    if authors_losing > 0 {
        warnings.push(format!(
            "{authors_losing} authors would lose read access to their own claims"
        ));
    }

    let response = PlanPreview {
        plan_id,
        state: "previewed".to_string(),
        mode: mode.to_string(),
        target_group_id: body.target_group_id,
        plan_digest: format!("b3:{}", hex::encode(digest)),
        // From the PERSISTED `created_at`, not from a local clock, so this
        // surface and `GET /plans/:id` derive the same field from one base.
        expires_at: created_at + chrono::Duration::hours(PLAN_TTL_HOURS),
        counts: PreviewCounts {
            seeds: selection.seed_count(),
            hull: selection.hull_count(),
            total: selection.item_count(),
            frozen,
            authors_losing_own_claims: authors_losing,
            not_visible_to_actor: not_visible,
            by_depth: selection.by_depth(),
        },
        sample: sample
            .into_iter()
            .map(|p| SampleItem {
                id: p.claim_id,
                preview: p.preview,
            })
            .collect(),
        boundary_edges: BoundaryEdges {
            claim_to_claim: boundary_counts.iter().map(|c| c.count).sum(),
            by_relationship: boundary_counts
                .into_iter()
                .map(|c| (c.relationship, c.count))
                .collect(),
            sample: boundary_sample,
        },
        warnings,
        requires_second_approver: selection.item_count() > SECOND_APPROVER_ITEM_THRESHOLD
            || authors_losing > 0,
    };

    Ok((axum::http::StatusCode::CREATED, Json(response)))
}

/// `GET /api/v1/admin/privatization/plans` — the plans the caller administers.
///
/// # Two independent controls, like its two siblings
///
/// This endpoint has no single target group for `require_plan_authority` to
/// check against, so its narrowing lives in the statement. Both filters are
/// evaluated on the actor's own stamped connection and both are load-bearing:
/// migration 087's SELECT policy, and the FINAL-PLAN §6.6 conjunction spliced
/// into `PrivatizationRepository::list_plans_conn`'s `WHERE` from the same
/// session helpers the policy uses. See that function's doc for why the first
/// revision — policy only — was the wrong trade here even though a handler-side
/// copy of a policy predicate is normally a place for drift.
///
/// # Errors
///
/// `401` no auth context; `403` without the `instance:admin` scope; `500` a
/// database fault.
///
/// # Divergence from FINAL-PLAN §6.5.7, recorded rather than silent
///
/// §6.5.7 gives this row the response `{ plans, next_cursor }` and the query
/// `?state=&target_group_id=&limit=&cursor=`. This build serves `plans` and no
/// `cursor`: the list truncates at `MAX_PAGE` instead of paging. Owned by the
/// apply/revert slice; also recorded in `docs/tenancy/progress.json`.
#[cfg(feature = "db")]
pub async fn list_plans(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Query(params): Query<PlanListQuery>,
) -> Result<Json<PlanListResponse>, ApiError> {
    use epigraph_db::repos::privatization::PrivatizationRepository;

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };
    // §6.5.7 gives this row `instance:admin`, with the target-group narrowing
    // done by the policy rather than by a per-group check — the endpoint has no
    // single target group to check against.
    crate::middleware::scopes::check_scopes(auth, &["instance:admin"])?;

    let limit = params.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let mut read = state.read_as(&viewer).await.map_err(scoped_read_error)?;
    let rows = PrivatizationRepository::list_plans_conn(
        &mut read,
        params.state.as_deref(),
        params.target_group_id,
        limit,
    )
    .await?;
    read.commit().await.map_err(scoped_read_error)?;

    Ok(Json(PlanListResponse {
        plans: rows.into_iter().map(summarise).collect(),
    }))
}

/// `GET /api/v1/admin/privatization/plans/:id` — one plan, with its counts.
///
/// Carries the same three-condition check as `POST /plans` (sec F7b): the plan
/// is loaded first, on the ACTOR's connection, so the check is applied to the
/// plan's own `target_group_id` rather than to one the caller supplied. A plan
/// the caller does not administer is not returned by the policy at all, so the
/// 404 below is reached before the check, and the check is what turns "you are
/// not an instance admin" into a 403 rather than into a false 404.
///
/// # Errors
///
/// `401` no auth context; `403` any of FINAL-PLAN §6.6's four conditions;
/// `404` no such plan, or one the caller may not read; `500` a database fault.
#[cfg(feature = "db")]
pub async fn get_plan(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(plan_id): Path<Uuid>,
) -> Result<Json<PlanSummary>, ApiError> {
    use epigraph_db::repos::privatization::PrivatizationRepository;

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let mut read = state.read_as(&viewer).await.map_err(scoped_read_error)?;
    let plan = PrivatizationRepository::load_plan_conn(&mut read, plan_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "privatization plan".to_string(),
            id: plan_id.to_string(),
        })?;
    read.commit().await.map_err(scoped_read_error)?;

    require_plan_authority(&state, auth, plan.target_group_id).await?;

    Ok(Json(summarise(plan)))
}

/// `GET /api/v1/admin/privatization/plans/:id/items` — one page of the frozen
/// set, rendered under the actor's own viewer.
///
/// Two independent narrowings apply and they answer different questions.
/// Migration 087's policy decides whether the caller may see that THIS PLAN has
/// items at all; the actor's `Viewer` decides which of those items may be named.
/// A caller who administers the target group but cannot read a selected claim
/// gets that claim as a contribution to `not_visible_to_actor` and to nothing
/// else.
///
/// # Errors
///
/// `401` no auth context; `403` any of FINAL-PLAN §6.6's four conditions;
/// `404` no such plan, or one the caller may not read; `500` a database fault.
#[cfg(feature = "db")]
pub async fn get_plan_items(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(plan_id): Path<Uuid>,
    Query(params): Query<PlanItemQuery>,
) -> Result<Json<PlanItemsResponse>, ApiError> {
    use epigraph_db::repos::privatization::PrivatizationRepository;

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let limit = params.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let offset = match params.cursor.as_deref() {
        None => 0,
        Some(c) => parse_cursor(c)?,
    };

    let mut read = state.read_as(&viewer).await.map_err(scoped_read_error)?;
    let plan = PrivatizationRepository::load_plan_conn(&mut read, plan_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "privatization plan".to_string(),
            id: plan_id.to_string(),
        })?;
    // COMMITTED BEFORE THE AUTHORITY CHECK, which leases a connection from a
    // DIFFERENT pool. Holding this one open across that acquire pins one
    // connection from each of two pools for the width of a request, and the
    // maintenance pool is deliberately the smallest in the process. `get_plan`
    // above already had this shape and this handler did not; two siblings
    // disagreeing about it is a legibility problem as well as a pool-pressure
    // one.
    read.commit().await.map_err(scoped_read_error)?;

    // THE CHECK GATES THE ITEM READ, and its position is deliberate. It comes
    // AFTER `load_plan_conn` so a plan the caller cannot see is a 404 rather
    // than a 403 — distinguishing the two would be an existence oracle over
    // every other admin's plans — and BEFORE `load_plan_items_conn`, so an
    // unauthorised caller never causes the entity-id read or the rendering pass
    // over it.
    require_plan_authority(&state, auth, plan.target_group_id).await?;

    let mut read = state.read_as(&viewer).await.map_err(scoped_read_error)?;
    let rows =
        PrivatizationRepository::load_plan_items_conn(&mut read, plan_id, offset, limit).await?;

    // The rendering pass. `rows` carries every entity id on the page; only the
    // ids `visible_previews` returns may be spoken aloud.
    let candidates: Vec<Uuid> = rows.iter().map(|r| r.entity_id).collect();
    let previews = PrivatizationRepository::visible_previews(&mut read, &viewer, &candidates)
        .await
        .map_err(selection_error)?;
    read.commit().await.map_err(scoped_read_error)?;

    let by_id: std::collections::HashMap<Uuid, String> = previews
        .into_iter()
        .map(|p| (p.claim_id, p.preview))
        .collect();

    // A POSITION, NEVER AN ENTITY ID. The first revision of this handler
    // serialised the last row's `entity_id` into the token, which put an id the
    // actor may only be permitted to COUNT into the response — the exact
    // property the `None` arm below and this module's header are about.
    let next_cursor = if i64::try_from(rows.len()).unwrap_or(i64::MAX) == limit {
        Some(format!(
            "{CURSOR_PREFIX}{}",
            offset.saturating_add(i64::try_from(rows.len()).unwrap_or(0))
        ))
    } else {
        None
    };

    let mut items = Vec::new();
    let mut not_visible = 0i64;
    for row in rows {
        match by_id.get(&row.entity_id) {
            Some(preview) => items.push(PlanItem {
                kind: row.kind,
                id: row.entity_id,
                depth: row.depth,
                via: row.via,
                state: row.state,
                preview: preview.clone(),
            }),
            // NO placeholder, NO redaction sentinel, NO id.
            None => not_visible += 1,
        }
    }

    Ok(Json(PlanItemsResponse {
        items,
        not_visible_to_actor: not_visible,
        next_cursor,
    }))
}

// =============================================================================
// HELPERS (db feature)
// =============================================================================

/// Re-run FINAL-PLAN §6.6's four conditions against a plan's own target group.
///
/// Takes its own maintenance connection for the reason
/// `require_instance_admin_for_group`'s doc gives: the plurality and role checks
/// count `group_memberships` rows, which migration 077's policy narrows on the
/// actor's connection.
#[cfg(feature = "db")]
async fn require_plan_authority(
    state: &AppState,
    auth: &crate::middleware::bearer::AuthContext,
    target_group_id: Uuid,
) -> Result<(), ApiError> {
    use epigraph_db::visibility::SystemReason;

    let (mut maint, _bypass) = state
        .maintenance_viewer(SystemReason::PrivatizationSelection)
        .await
        .map_err(|e| {
            tracing::error!(
                target: "tenancy.privatization",
                error = %e,
                "could not acquire the maintenance connection for the authority check"
            );
            ApiError::InternalError {
                message: "Failed to acquire a maintenance connection".to_string(),
            }
        })?;
    crate::middleware::instance_authz::require_instance_admin_for_group(
        auth,
        target_group_id,
        &mut maint,
    )
    .await?;
    Ok(())
}

/// Resolve the selector's seed arm to claim ids, unfiltered.
///
/// # `node_cap` bounds the SEED set too, and it refuses rather than truncates
///
/// `ClaimRepository::list_by_labels` takes a `LIMIT`, and a predicate matching
/// more claims than the limit would come back as an ARBITRARY subset — the query
/// has no total ordering that makes the survivors reproducible. That is exactly
/// the silent, nondeterministic truncation `select_closure`'s overflow probe
/// exists to refuse, one layer earlier: the plan would be frozen over a set the
/// operator did not choose, digested, and returned with a `201`.
///
/// So the predicate arm asks for `node_cap + 1` and refuses the whole request
/// when it gets them. The refusal is its own message rather than
/// `SelectionRefusal::NodeCapExceeded`, which is about the CLOSURE overflowing;
/// naming the seeds is what tells an operator to narrow the selector rather than
/// the traversal. It also bounds the memory: `list_by_labels` materialises whole
/// `Claim` rows, content included.
#[cfg(feature = "db")]
async fn resolve_seeds(
    conn: &mut sqlx::PgConnection,
    bypass: &epigraph_db::visibility::Viewer,
    seeds: &PlanSeeds,
    node_cap: i32,
) -> Result<Vec<Uuid>, ApiError> {
    if seeds.saved_query.is_some() {
        // FINAL-PLAN §6.5.1: "A saved query re-evaluated at apply time is a
        // STANDING privatization rule, which must run on every insert — a
        // trigger, i.e. the write path. Ship the schema slot; do not ship the
        // semantics."
        return Err(ApiError::NotImplemented {
            feature: "seeds.saved_query".to_string(),
        });
    }
    let arms = usize::from(seeds.ids.is_some()) + usize::from(seeds.predicate.is_some());
    if arms != 1 {
        return Err(ApiError::BadRequest {
            message: "seeds must name exactly one of ids, predicate, saved_query".to_string(),
        });
    }

    if let Some(ids) = &seeds.ids {
        // The `ids` arm is exact by construction — the operator typed the list —
        // so there is nothing to truncate, but a list longer than the cap would
        // be refused by `select_closure` anyway. Refused here so the message
        // names the seeds.
        if i64::try_from(ids.claims.len()).unwrap_or(i64::MAX) > i64::from(node_cap) {
            return Err(ApiError::BadRequest {
                message: format!(
                    "seeds.ids names {} claims, which exceeds closure.node_cap {node_cap}",
                    ids.claims.len()
                ),
            });
        }
        return Ok(ids.claims.clone());
    }

    let predicate = seeds.predicate.as_ref().expect("exactly one arm");
    // Refused rather than ignored: a selector that quietly drops a narrowing
    // clause selects MORE than the operator asked for.
    let mut unserved = Vec::new();
    if predicate.agent_id.is_some() {
        unserved.push("agent_id");
    }
    if predicate.properties_contains.is_some() {
        unserved.push("properties_contains");
    }
    if predicate.created_before.is_some() {
        unserved.push("created_before");
    }
    if !unserved.is_empty() {
        return Err(ApiError::BadRequest {
            message: format!(
                "seeds.predicate fields not served by this build: {}. They are refused rather \
                 than ignored — a dropped narrowing clause selects more than you asked for.",
                unserved.join(", ")
            ),
        });
    }
    if predicate.labels.is_empty() {
        return Err(ApiError::BadRequest {
            message: "seeds.predicate.labels must name at least one label".to_string(),
        });
    }

    let rows = epigraph_db::repos::claim::ClaimRepository::list_by_labels(
        &mut *conn,
        bypass,
        epigraph_db::repos::claim::LabelQuery {
            labels: &predicate.labels,
            exclude_labels: &predicate.exclude_labels,
            current_only: predicate.current_only.unwrap_or(true),
            min_truth: 0.0,
            // ONE MORE ROW THAN THE CAP ALLOWS, so overflow is detected rather
            // than absorbed. See this function's doc.
            limit: i64::from(node_cap).saturating_add(1),
            offset: 0,
        },
    )
    .await?;
    if i64::try_from(rows.len()).unwrap_or(i64::MAX) > i64::from(node_cap) {
        return Err(ApiError::BadRequest {
            message: format!(
                "seeds.predicate matches more than closure.node_cap ({node_cap}) claims; narrow \
                 the labels or raise the cap. The selector is refused rather than truncated — a \
                 truncated seed set is not a smaller privatization, it is an arbitrary one"
            ),
        });
    }
    Ok(rows.into_iter().map(|(c, _)| c.id.as_uuid()).collect())
}

/// Map a plan row onto the list/summary shape, deriving `expires_at`.
#[cfg(feature = "db")]
fn summarise(row: epigraph_db::repos::privatization::PlanRow) -> PlanSummary {
    PlanSummary {
        plan_id: row.id,
        state: row.state,
        mode: row.mode,
        target_group_id: row.target_group_id,
        item_count: row.item_count,
        authors_losing_count: row.authors_losing_count,
        created_at: row.created_at,
        expires_at: row.created_at + chrono::Duration::hours(PLAN_TTL_HOURS),
    }
}

/// The `o:` prefix of the page cursor. Present so the token stays visibly
/// opaque, and so the previous `kind:uuid` spelling is rejected unambiguously
/// rather than half-parsed.
#[cfg(feature = "db")]
const CURSOR_PREFIX: &str = "o:";

/// `o:<offset>` — a POSITION in `load_plan_items_conn`'s frozen, totally
/// ordered item set.
///
/// # It carries no entity id, in EITHER direction
///
/// The token the handler emits is a position, and the token the handler accepts
/// is a position. Both halves matter and only fixing the outbound one would
/// have left the inbound one: an ordering key chosen by the caller, applied to
/// rows the caller may be permitted to see only as a count, with the per-page
/// `not_visible_to_actor` figure as the answer. Positions cannot express that
/// question.
///
/// A negative offset is a Postgres error rather than an empty page, so it is
/// refused here as a 400 rather than reaching the statement as a 500.
///
/// # Errors
///
/// `400` for anything that is not `o:` followed by a non-negative integer.
#[cfg(feature = "db")]
fn parse_cursor(cursor: &str) -> Result<i64, ApiError> {
    let malformed = || ApiError::BadRequest {
        message: "malformed cursor; pass back the `next_cursor` of the previous page unchanged"
            .to_string(),
    };
    let digits = cursor.strip_prefix(CURSOR_PREFIX).ok_or_else(malformed)?;
    let offset: i64 = digits.parse().map_err(|_| malformed())?;
    if offset < 0 {
        return Err(malformed());
    }
    Ok(offset)
}

/// A selection refusal is a 400; a database fault is a 500.
///
/// FINAL-PLAN §3.1 requires exceeding `node_cap` or `max_depth` to be "a 400,
/// not a truncation", and the repo layer already models the two as separate
/// error kinds; this only preserves the distinction across the HTTP boundary.
#[cfg(feature = "db")]
fn selection_error(err: epigraph_db::repos::privatization::SelectionError) -> ApiError {
    use epigraph_db::repos::privatization::SelectionError;
    match err {
        SelectionError::Refused(refusal) => ApiError::BadRequest {
            message: refusal.to_string(),
        },
        SelectionError::Db(e) => ApiError::from(e),
    }
}

/// Migration 081's plan guard `RAISE`s when the target group is too young or has
/// too few other admins.
///
/// The handler checks both conditions first, so reaching the guard means the two
/// disagreed — a race, or a drifted threshold. Reported as a 403 rather than a
/// 500 because the guard is the authority and its answer is "no", not "broken".
///
/// # Discriminated on SQLSTATE, and answered opaquely
///
/// The first revision matched the formatted error TEXT for `"target group"` or
/// `"admins"` and then returned that same raw text to the client as the refusal
/// reason. Two faults in one function: `DbError::QueryFailed`'s Display carries
/// whatever the driver formatted, so an unrelated fault whose message happened
/// to contain either token was reported as an authorization refusal; and
/// [`scoped_read_error`] three functions below states the house rule the other
/// way round — log the internal text, answer opaquely. Migration 081 raises
/// every one of its refusals `USING ERRCODE = '42501'`, which is a discriminator
/// that does not move when the message is reworded, so that is what is matched.
///
/// `42501` is also what a row-level-security denial reports. Both are the same
/// answer to the caller — the database refused this write — and the raw error is
/// logged either way, so the diagnosis is not lost.
#[cfg(feature = "db")]
fn plan_write_error(err: epigraph_db::DbError) -> ApiError {
    let insufficient_privilege = matches!(
        &err,
        epigraph_db::DbError::QueryFailed { source }
            if source
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref()
                == Some("42501")
    );
    if insufficient_privilege {
        tracing::error!(
            target: "tenancy.privatization",
            error = %err,
            handler = "create_plan",
            "the database refused the plan insert"
        );
        return ApiError::Forbidden {
            reason: "the target group does not satisfy this instance's privatization conditions, \
                     or the database refused the write"
                .to_string(),
        };
    }
    ApiError::from(err)
}

/// `read_as`'s refusal reason is internal design prose; log it and answer
/// opaquely. Same shape as `routes/lineage.rs`.
#[cfg(feature = "db")]
fn scoped_read_error(e: epigraph_db::DbError) -> ApiError {
    tracing::error!(
        target: "tenancy.scoped_read",
        error = %e,
        handler = "privatization",
        "could not acquire a viewer-stamped connection"
    );
    ApiError::InternalError {
        message: "Failed to acquire a scoped connection".to_string(),
    }
}

// =============================================================================
// PLACEHOLDERS (no db feature)
//
// `ViewerExtractor` and everything it reaches are `#[cfg(feature = "db")]`,
// while the router that names these handlers is not. Without these arms a
// `--no-default-features` build of `epigraph-api` fails — a configuration
// `cargo test --workspace --all-targets` never exercises.
// =============================================================================

/// `POST /api/v1/admin/privatization/plans` without the `db` feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn create_plan(
    State(_state): State<AppState>,
    Json(_body): Json<CreatePlanRequest>,
) -> Result<Json<PlanPreview>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `GET /api/v1/admin/privatization/plans` without the `db` feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn list_plans(
    State(_state): State<AppState>,
    Query(_params): Query<PlanListQuery>,
) -> Result<Json<PlanListResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `GET /api/v1/admin/privatization/plans/:id` without the `db` feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn get_plan(
    State(_state): State<AppState>,
    Path(_plan_id): Path<Uuid>,
) -> Result<Json<PlanSummary>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `GET /api/v1/admin/privatization/plans/:id/items` without the `db` feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn get_plan_items(
    State(_state): State<AppState>,
    Path(_plan_id): Path<Uuid>,
    Query(_params): Query<PlanItemQuery>,
) -> Result<Json<PlanItemsResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}
