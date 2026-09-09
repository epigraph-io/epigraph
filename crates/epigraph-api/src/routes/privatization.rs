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
//! **The two manifest routes are the carve-out, and they are a carve-out from
//! the rule's rationale rather than an exception to it.** `seal_manifest` and
//! `unseal_manifest` page with a KEYSET cursor over `claims.id`: they emit the
//! last claim id on the page as `next_cursor` and accept one back. The rule
//! above forbids that everywhere else because an id the actor may only count
//! must not leak through a token. These two endpoints serve the full plaintext
//! or full ciphertext of exactly the rows they page over, under §6.6's three
//! conditions, so a cursor discloses nothing the response body has not already
//! disclosed — and a keyset page over an immutable frozen item set is what stops
//! a concurrent seal from making an OFFSET page skip a row, which on this path
//! would be a silently unsealed claim.
//!
//! # Nothing here applies anything
//!
//! `approve`, `apply`, `abort` and `revert` now exist, and none of them moves a
//! claim. FINAL-PLAN §6.5.5: not one transaction, a job. `apply` validates,
//! writes a `security_events` row, flips `state='applying'`, enqueues and
//! returns `202`; the rows move in `epigraph-jobs/src/privatization.rs`, which
//! **re-validates every one of those decisions from the database before it
//! touches a row (sec F5)**. What these four routes decide is what the OPERATOR
//! is told.
//!
//! The UPDATE policies that make them possible are migration **088**'s. Under
//! `FORCE` a command with no policy is denied to every role including a bypass
//! connection, which is why the preview slice shipped four read routes and
//! stopped; `rls_enforcement.rs::DELIBERATELY_UNCOVERED` assigned both UPDATE
//! pairs to this slice by name and both rows are deleted in the same commit as
//! the migration.
//!
//! # What this module still does NOT do, and why
//!
//! The seal/unseal manifest ceremony (`seal-manifest`, `seal-commit`,
//! `unseal-manifest`, `unseal-commit`) is HERE as of PR-21, and `create_plan`
//! no longer answers `501` for `mode="seal"`. The encryption itself is not:
//! `crates/epigraph-privacy` supplies it and it runs on the CLIENT
//! (`epigraph-privatize`). What this module owns is the manifest, its digest,
//! and the all-or-nothing commit — the server's half of a ceremony whose key it
//! must never hold.
//!
//! The MCP tools §6.5.7 names are absent too;
//! they discharge no acceptance clause and are recorded as descoped in
//! `docs/tenancy/progress.json` rather than shipped ahead of the surface they
//! would mirror.
//!
//! `PATCH /claims/:id/visibility` — the plan's "retained sugar, rewritten" — is
//! **not** created here. There is nothing to rewrite: no such route exists in
//! this tree, so shipping it would be creating a NEW single-request
//! declassification/reclassification power, which is the shape PR-11 and PR-14
//! deleted (`assign_ownership`, `update_partition`). That is a decision for a
//! slice that argues it, not a side effect of building the plan surface.

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
    /// What applying this plan does and does not revoke.
    pub side_effects: SideEffects,
}

/// FINAL-PLAN §6.7 point 1's third home for the revocation disclosure.
///
/// The plan requires the sentence in three places, and this is the one an
/// operator reads BEFORE acting rather than after: a privatization preview is
/// the moment someone decides whether moving a subgraph into a group is
/// sufficient, and "we can revoke it later" is the belief that decision most
/// often rests on.
///
/// PR-20's *Acceptance* line names only two of the three homes. §6.7 point 1
/// names three, and it is the substantive specification; the two-item list is
/// an abbreviation of it, not a descope. Recorded in
/// `docs/tenancy/progress.json` under `plan_corrections`.
#[derive(Serialize, Debug)]
pub struct SideEffects {
    /// The §6.7 sentence, verbatim, from one constant shared with the rotate
    /// response — see [`crate::tenancy_disclosure`].
    pub revocation: &'static str,
    /// **Seal mode only.** The derived tables whose rows this plan DESTROYS.
    ///
    /// PR-21's share of `F-PR18b-preview-schema-is-a-subset`. §6.5.4 requires
    /// the preview to state, before the admin clicks, exactly which derived
    /// rows a seal destroys — because they are deleted rather than encrypted,
    /// and unseal does not bring them back. `None` for `restrict`, which
    /// destroys nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroys_derived_rows: Option<&'static [&'static str]>,
    /// **Seal mode only.** The one loss that is not re-derivable at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unrecoverable: Option<&'static str>,
    /// **Seal mode only.** That the server cannot undo this by itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reversibility: Option<&'static str>,
}

/// The tables a `mode='seal'` plan empties of rows, named in the preview.
///
/// Kept beside [`SideEffects`] rather than aliased to the repo layer's
/// `SEAL_DELETE_TABLES`, because these are two different statements: that one
/// is what the mutation DOES, this one is what the operator is TOLD. A single
/// shared constant would make them agree by construction and therefore stop
/// saying anything about the consent surface.
///
/// The agreement is asserted instead, as an exact set, by
/// `epigraph-api/tests/privatization_seal.rs::the_preview_names_exactly_the_tables_the_seal_deletes`.
/// Drift here is a preview that under-reports what a seal destroys, which is
/// consent the operator did not give.
pub const SEAL_DESTROYS: &[&str] = &[
    "triples",
    "entity_mentions",
    "experiment_entity_mentions",
    "reasoning_traces",
    "challenges",
    "experiment_triples",
];

/// What a seal takes that no unseal returns.
///
/// The second clause is not decoration. A source fragment is linked to claims
/// `(claim_id, fragment_id)`, so one fragment can back several claims, and
/// blanking it takes the source text away from every claim that cites it —
/// including claims outside this plan. The alternative, skipping a shared
/// fragment, would leave the SEALED claim's own source text in the corpus in
/// plaintext, which §6.5.4 calls worse than not sealing at all. So the loss is
/// real, it is chosen, and it is stated here before the admin clicks.
const SEAL_UNRECOVERABLE: &str = "harvester_fragments source text (content_text and \
     context_window) is blanked and is NOT restored by unseal; re-extraction cannot recover it \
     because the fragment text is the source. A fragment cited by claims OUTSIDE this plan is \
     blanked for those claims too: the fragment is one row, and leaving it would leave the sealed \
     claim's own source text readable";

/// What a seal costs that a restrict does not.
const SEAL_NOT_SERVER_REVERSIBLE: &str = "a seal is not server-reversible: the server holds no \
     key, so only a key-holding admin can unseal, and until every item is unsealed this plan \
     cannot be reverted";

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

/// One row of `GET /plans`, and the body of `GET /plans/:id`.
///
/// # The apply-time block is the LIVE PROGRESS half of §6.5.7
///
/// `F-PR18b-preview-schema-is-a-subset` records that §6.5.7 gives
/// `GET /plans/:id` "preview + live progress" and that 18b served a summary,
/// because live progress is the cursor and the per-item state and nothing could
/// produce either. This slice produces both, so the fields arrive with the code
/// that moves them.
///
/// **`drift_count`, not `drift_ids`.** The drift set is a list of claim ids that
/// a plan administrator may not be entitled to READ — administering a target
/// group is not the same property as being able to read every claim the rescan
/// found — and this response crosses no `Viewer`. The ids are reachable through
/// the follow-up plan's own item list, where the rendering pass applies.
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
    /// The second instance admin who approved, if any.
    pub approved_by: Option<Uuid>,
    /// When the approval was given.
    pub approved_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The agent whose `apply` or `revert` dispatched the job.
    pub dispatched_by: Option<Uuid>,
    /// The depth band the last committed batch reached. Apply walks deepest
    /// first, so this DESCENDS while a plan is `applying`.
    pub cursor_depth: Option<i32>,
    /// How many restatement-tier drifts the post-apply rescan found.
    pub drift_count: i64,
    /// `item state -> count`. Served by `GET /plans/:id` and `null` on the list
    /// endpoint, which would otherwise run one aggregate per row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items_by_state: Option<std::collections::BTreeMap<String, i64>>,
    /// When the plan was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Derived: `created_at + 4h`.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// `POST /plans/:id/apply` body.
#[derive(Deserialize, Debug, Clone)]
pub struct ApplyRequest {
    /// The `b3:`-prefixed digest the preview returned. An apply that does not
    /// echo the CURRENT digest is refused with `409`: the corpus has moved and
    /// the operator is approving a plan they have not seen.
    pub plan_digest: String,
    /// Required when `mode='seal'` and the plan costs an author access to their
    /// own claims.
    #[serde(default)]
    pub acknowledge_author_loss: Option<bool>,
}

/// `POST /plans/:id/revert` body.
#[derive(Deserialize, Debug, Clone)]
pub struct RevertRequest {
    /// The digest, echoed for the same reason `apply` echoes it.
    pub plan_digest: String,
}

/// The `202` body of `apply` and `revert`.
#[derive(Serialize, Debug)]
pub struct DispatchResponse {
    /// The plan.
    pub plan_id: Uuid,
    /// The enqueued job.
    pub job_id: Uuid,
    /// `applying` or `reverting`.
    pub state: String,
    /// The correlation id shared by this request's `security_events` row, the
    /// job payload and every `privatization_audit` row the run writes. It is
    /// what makes the three joinable after the fact.
    pub correlation_id: String,
}

/// The `200` body of `approve` and `abort`.
#[derive(Serialize, Debug)]
pub struct PlanStateResponse {
    /// The plan.
    pub plan_id: Uuid,
    /// Its new state.
    pub state: String,
}

/// `GET /admin/privatization/audit` query.
#[derive(Deserialize, Debug, Default)]
pub struct AuditQueryParams {
    /// Restrict to one plan.
    pub plan_id: Option<Uuid>,
    /// Restrict to one entity.
    pub entity_id: Option<Uuid>,
    /// Only rows at or after this instant.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// Page size, clamped to `MAX_PAGE`.
    pub limit: Option<i64>,
}

/// `GET /admin/privatization/audit` body.
#[derive(Serialize, Debug)]
pub struct AuditResponse {
    /// The rows migration 083's policy admitted.
    pub events: Vec<AuditEvent>,
}

/// One audit row.
#[derive(Serialize, Debug)]
pub struct AuditEvent {
    /// The row's own id.
    pub id: i64,
    /// The plan.
    pub plan_id: Uuid,
    /// Who acted.
    pub actor_agent_id: Uuid,
    /// What they did.
    pub action: String,
    /// `claim`|`evidence`, when the row is about one entity.
    pub kind: Option<String>,
    /// The entity. Present only where migration 083's policy admitted the
    /// entity-level arm — an instance admin who does not administer the plan's
    /// target group sees the plan-level rows and not this.
    pub entity_id: Option<Uuid>,
    /// Tenancy before the action.
    pub before_visibility: Option<String>,
    /// Tenancy after the action.
    pub after_visibility: Option<String>,
    /// Joins this row to a `security_events` row and to a job payload.
    pub correlation_id: Option<String>,
    /// When.
    pub created_at: chrono::DateTime<chrono::Utc>,
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
// SEAL CEREMONY WIRE TYPES (FINAL-PLAN §6.5.6)
//
// Declared OUTSIDE the `db` feature, like every other type in this module, so
// the `#[cfg(not(feature = "db"))]` placeholder handlers can name them.
// =============================================================================

/// `?cursor=&limit=` on either manifest.
#[derive(Deserialize, Debug, Clone)]
pub struct ManifestQuery {
    /// Keyset cursor: the last `claim_id` of the previous page, exclusive.
    #[serde(default)]
    pub cursor: Option<Uuid>,
    /// Page size, 1..=500.
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET …/seal-manifest` response.
#[derive(Serialize, Debug)]
pub struct SealManifest {
    /// The plan.
    pub plan_id: Uuid,
    /// The active key epoch every ciphertext must be bound to.
    pub epoch: i32,
    /// The padding bucket the commit's ciphertexts must be a multiple of.
    pub pad_to: i32,
    /// BLAKE3 over this page's TCB SHAPE, `b3:` + hex. The commit echoes it.
    pub manifest_digest: String,
    /// The last `claim_id` on this page, or `None` at the end of the stream.
    pub next_cursor: Option<Uuid>,
    /// The page.
    pub items: Vec<SealManifestEntry>,
}

/// One claim's plaintext TCB.
#[derive(Serialize, Debug)]
pub struct SealManifestEntry {
    /// The claim.
    pub claim_id: Uuid,
    /// `claims.content`.
    pub content: String,
    /// `claims.labels`.
    pub labels: Vec<String>,
    /// `claims.properties`.
    pub properties: serde_json::Value,
    /// Every `claim_versions` row.
    pub versions: Vec<ManifestVersion>,
    /// Every `evidence` row.
    pub evidence: Vec<ManifestEvidence>,
}

/// One `claim_versions` row's plaintext.
#[derive(Serialize, Debug)]
pub struct ManifestVersion {
    /// `claim_versions.id`.
    pub id: Uuid,
    /// `claim_versions.content`.
    pub content: String,
}

/// One `evidence` row's plaintext.
#[derive(Serialize, Debug)]
pub struct ManifestEvidence {
    /// `evidence.id`.
    pub id: Uuid,
    /// `evidence.raw_content`.
    pub raw_content: Option<String>,
    /// `evidence.properties`.
    pub properties: serde_json::Value,
}

/// `POST …/seal-commit` body.
#[derive(Deserialize, Debug, Clone)]
pub struct SealCommitRequest {
    /// The digest the manifest served. Recomputed server-side from the
    /// DATABASE, so a TCB that grew since is a `409` rather than a partial seal.
    pub manifest_digest: String,
    /// The page's ciphertext.
    pub items: Vec<SealCommitEntry>,
}

/// One claim's ciphertext. Every field is required; see the repo type's doc.
#[derive(Deserialize, Debug, Clone)]
pub struct SealCommitEntry {
    /// The claim.
    pub claim_id: Uuid,
    /// Base64 `EncryptedPayload::to_bytes()` of the padded content.
    pub content_ct_b64: String,
    /// Base64 ciphertext of the padded labels.
    pub labels_ct_b64: String,
    /// Base64 ciphertext of the padded properties.
    pub properties_ct_b64: String,
    /// Base64 BLAKE3 over the content ciphertext, 32 bytes.
    pub content_hash_b64: String,
    /// One entry per `claim_versions` row.
    pub versions: Vec<CommitVersion>,
    /// One entry per `evidence` row.
    pub evidence: Vec<CommitEvidence>,
}

/// One `claim_versions` row's ciphertext.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommitVersion {
    /// `claim_versions.id`.
    pub id: Uuid,
    /// Base64 ciphertext.
    pub ct_b64: String,
}

/// One `evidence` row's ciphertext.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommitEvidence {
    /// `evidence.id`.
    pub id: Uuid,
    /// Base64 ciphertext of `raw_content`.
    pub ct_b64: String,
    /// Base64 ciphertext of `properties`.
    pub props_ct_b64: String,
}

/// `GET …/unseal-manifest` response. Ciphertext only.
#[derive(Serialize, Debug)]
pub struct UnsealManifest {
    /// The plan.
    pub plan_id: Uuid,
    /// BLAKE3 over this page's TCB shape.
    pub manifest_digest: String,
    /// The last `claim_id` on this page.
    pub next_cursor: Option<Uuid>,
    /// The page.
    pub items: Vec<UnsealManifestEntry>,
}

/// One claim's ciphertext, as served for unsealing.
#[derive(Serialize, Debug)]
pub struct UnsealManifestEntry {
    /// The claim.
    pub claim_id: Uuid,
    /// The epoch this row's ciphertext is bound to. It is the ROW's epoch and
    /// not the group's active one, because a rotation retires an epoch without
    /// re-encrypting anything — see §6.7.
    pub epoch: i32,
    /// The padding bucket to strip after decrypting.
    pub pad_to: i32,
    /// Base64 `claim_encryption.encrypted_content`.
    pub content_ct_b64: String,
    /// Base64 `claim_encryption.encrypted_labels`.
    pub labels_ct_b64: Option<String>,
    /// Base64 `claim_encryption.encrypted_properties`.
    pub properties_ct_b64: Option<String>,
    /// `claim_version_encryption` rows.
    pub versions: Vec<CommitVersion>,
    /// `evidence_encryption` rows.
    pub evidence: Vec<CommitEvidence>,
}

/// `POST …/unseal-commit` body.
#[derive(Deserialize, Debug, Clone)]
pub struct UnsealCommitRequest {
    /// The restored plaintext.
    pub items: Vec<UnsealCommitEntry>,
}

/// One claim's restored plaintext.
#[derive(Deserialize, Debug, Clone)]
pub struct UnsealCommitEntry {
    /// The claim.
    pub claim_id: Uuid,
    /// The restored `claims.content`.
    pub content: String,
    /// Base64 BLAKE3 over the restored plaintext, 32 bytes.
    pub content_hash_b64: String,
    /// The restored `claims.labels`.
    #[serde(default)]
    pub labels: Vec<String>,
    /// The restored `claims.properties`.
    #[serde(default)]
    pub properties: serde_json::Value,
    /// The restored `claim_versions` rows.
    #[serde(default)]
    pub versions: Vec<UnsealCommitVersionEntry>,
    /// The restored `evidence` rows.
    #[serde(default)]
    pub evidence: Vec<UnsealCommitEvidenceEntry>,
}

/// One restored `claim_versions` row.
#[derive(Deserialize, Debug, Clone)]
pub struct UnsealCommitVersionEntry {
    /// `claim_versions.id`.
    pub id: Uuid,
    /// The restored content.
    pub content: String,
}

/// One restored `evidence` row.
#[derive(Deserialize, Debug, Clone)]
pub struct UnsealCommitEvidenceEntry {
    /// `evidence.id`.
    pub id: Uuid,
    /// The restored `raw_content`.
    pub raw_content: Option<String>,
    /// The restored `properties`.
    #[serde(default)]
    pub properties: serde_json::Value,
}

/// `POST …/seal-commit` and `POST …/unseal-commit` response.
#[derive(Serialize, Debug)]
pub struct CommitResponse {
    /// The plan.
    pub plan_id: Uuid,
    /// How many items this call moved.
    pub committed: usize,
    /// How many were already in the requested state. NOT a failure: a
    /// re-delivered commit is a no-op, and reporting the difference is how a
    /// client learns it was re-delivered rather than inferring it from silence.
    pub already_done: usize,
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
/// a refusal and not a truncation — and, for `mode='seal'`, a `pad_to` of 0,
/// which migration 080's `pp_seal_needs_pad` forbids; `501` a `saved_query`
/// seed; `500` a database fault.
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

    // PR-21 REMOVED THE `mode == "seal"` 501 ARM. Both phases of §6.5.6's
    // ceremony now exist — `seal-manifest`/`seal-commit` and their unseal
    // mirrors — so a seal preview is no longer a promise about work that does
    // not exist.
    let mode = body.mode.as_deref().unwrap_or("restrict");
    if !matches!(mode, "restrict" | "seal") {
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
    // Migration 080's `pp_seal_needs_pad` CHECK says the same thing and binds
    // the maintenance connection too. Saying it here makes it a 400 with a
    // sentence rather than a 500 carrying `23514`, and it also settles §6.5.4's
    // "pad_to = 0 requires an explicit override": there is no override to
    // build, because the applied schema forbids the combination outright.
    if mode == "seal" && pad_to == 0 {
        return Err(ApiError::BadRequest {
            message: "mode='seal' requires pad_to > 0. Without padding, octet_length of the \
                      stored ciphertext is a function of the plaintext length, which is the \
                      side channel seal exists to close"
                .to_string(),
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
        side_effects: SideEffects {
            revocation: crate::tenancy_disclosure::ROTATION_DOES_NOT_REVOKE_PAST_ACCESS,
            destroys_derived_rows: (mode == "seal").then_some(SEAL_DESTROYS),
            unrecoverable: (mode == "seal").then_some(SEAL_UNRECOVERABLE),
            reversibility: (mode == "seal").then_some(SEAL_NOT_SERVER_REVERSIBLE),
        },
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

    let plan = load_plan_for_actor(&state, &viewer, plan_id).await?;
    require_plan_authority(&state, auth, plan.target_group_id).await?;

    // THE LIVE PROGRESS BLOCK, on the ACTOR's connection. 087's policy on
    // `privatization_plan_items` is what makes this a histogram of THIS
    // caller's plan rather than of any plan whose id they can guess, and the
    // aggregate returns counts and no entity ids either way.
    let mut read = state.read_as(&viewer).await.map_err(scoped_read_error)?;
    let by_state = PrivatizationRepository::item_state_counts_conn(&mut read, plan_id).await?;
    read.commit().await.map_err(scoped_read_error)?;

    let mut summary = summarise(plan);
    summary.items_by_state = Some(by_state);
    Ok(Json(summary))
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
// APPROVE / APPLY / ABORT / REVERT — the state-changing surface.
//
// Every one of the four has the same skeleton and the order of its steps is the
// control, not a style:
//
//   1. load the plan on the ACTOR's stamped connection. Migration 087's SELECT
//      policy is what decides whether the plan exists FOR THIS CALLER, and a
//      plan they do not administer is a 404 rather than a 403 — distinguishing
//      the two would be an existence oracle over every other admin's plans.
//   2. `require_plan_authority` against the plan's OWN `target_group_id`, on the
//      maintenance connection, so the refusal is a 403 with a reason (sec F7b).
//   3. the route's own preconditions — TTL, digest, approver, mode — each with
//      its own status, so an operator can tell "go and get an approval" (428)
//      from "the plan moved" (409) from "re-run the preview" (410).
//   4. ONE transaction on the maintenance connection: the `security_events`
//      row, the conditional state flip, the audit row and the enqueue.
//
// STEP 4 IS ONE TRANSACTION AND THAT IS §6.5.5's SIXTH CONDITION. The handler
// refuses to dispatch unless `dispatched_by` matches the `agent_id` on the
// `security_events` row for this `correlation_id`; an event written on a
// different connection can commit while the flip rolls back, leaving a
// correlation id that would authorise a plan nobody dispatched.
//
// NONE OF THIS IS THE AUTHORIZATION FOR THE MUTATION. FINAL-PLAN §6.5.5: "The
// handler re-validates. The HTTP layer's checks are not the authorization
// (sec F5)." What these four routes decide is what the OPERATOR is told; what
// the rows do is decided again, from the database, in
// `epigraph-jobs/src/privatization.rs`.
// =============================================================================

/// `POST /api/v1/admin/privatization/plans/:id/approve` — the second pair of
/// eyes.
///
/// # Acceptance clause 3 is here; clause 4 is a 404 or a 403, never a 409
///
/// FINAL-PLAN's PR-18 acceptance line asks for two 409s on this route: "approve
/// by `created_by`" and "approve by an instance admin who is not an admin of the
/// target group". The first is below and is a 409.
///
/// **The second is a 404 where migration 087's read policy binds, and a 403 from
/// §6.6's condition 4 where it does not** — a superuser or `BYPASSRLS`
/// connection, which is what a test fixture usually has. 087's
/// `privatization_plans_read` requires instance-admin AND
/// group-admin-of-target, so where the policy applies an instance admin who does
/// not administer the target group cannot see the plan at all and step 1 answers
/// before step 3 can; where it does not, step 2 answers. Both are strictly more
/// conservative than the specified 409 — both disclose less — and returning 409
/// would require the handler to tell a caller that a plan they may not read
/// exists. The divergence is recorded in `docs/tenancy/progress.json`, and the
/// regression asserts the DISJUNCTION rather than pinning either status, so a
/// fixture's connection posture is not encoded as a contract.
///
/// # Errors
///
/// `401` no auth context; `403` any of FINAL-PLAN §6.6's four conditions;
/// `404` no such plan, or one the caller may not read; `409` the actor is the
/// plan's author, or the plan is not `previewed`, or it already has an approver;
/// `410` the plan has aged out; `500` a database fault.
#[cfg(feature = "db")]
pub async fn approve_plan(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(plan_id): Path<Uuid>,
) -> Result<Json<PlanStateResponse>, ApiError> {
    use epigraph_db::repos::privatization::{PlanTransition, PrivatizationRepository};

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let plan = load_plan_for_actor(&state, &viewer, plan_id).await?;
    let actor = require_plan_authority(&state, auth, plan.target_group_id).await?;

    refuse_if_expired(&plan)?;

    // FOUR EYES. Migration 080's `pp_four_eyes` CHECK says the same thing and
    // binds the maintenance connection too; this is here so the answer is a 409
    // with a sentence rather than a 500 carrying `23514`.
    if actor == plan.created_by {
        return Err(ApiError::Conflict {
            reason: "a plan cannot be approved by the agent that created it; a second instance \
                     admin who also administers the target group must approve"
                .to_string(),
        });
    }
    if plan.state != "previewed" {
        return Err(ApiError::Conflict {
            reason: format!(
                "a plan can only be approved while it is 'previewed'; this one is \
                             '{}'",
                plan.state
            ),
        });
    }

    let (mut maint, _bypass) = maintenance(&state).await?;
    let mut tx = sqlx::Connection::begin(&mut *maint)
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;
    let moved = PrivatizationRepository::transition_plan_conn(
        &mut tx,
        plan_id,
        PlanTransition::Approve { approver: actor },
    )
    .await
    .map_err(plan_write_error)?;
    if moved == 0 {
        // The `WHERE` refused: something moved the plan between the read above
        // and this statement. A 409 and not a 500 — the database's answer is
        // "no", not "broken".
        return Err(ApiError::Conflict {
            reason: "the plan moved while it was being approved; re-read it and try again"
                .to_string(),
        });
    }
    PrivatizationRepository::record_plan_audit_conn(
        &mut tx,
        epigraph_db::repos::privatization::PlanAuditEntry {
            plan_id,
            actor_agent_id: actor,
            action: "plan.approve",
            kind: None,
            entity_id: None,
            plan_digest: plan.plan_digest.as_deref(),
            correlation_id: None,
        },
    )
    .await
    .map_err(plan_write_error)?;
    tx.commit()
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;

    Ok(Json(PlanStateResponse {
        plan_id,
        state: "approved".to_string(),
    }))
}

/// `POST /api/v1/admin/privatization/plans/:id/apply` — validate, flip, enqueue,
/// `202`.
///
/// # It does not apply anything
///
/// FINAL-PLAN §6.5.5: not one transaction, a job. This handler's whole output is
/// a `jobs` row and a plan in `applying`; the rows move in
/// `epigraph-jobs/src/privatization.rs`, which re-validates every condition
/// below from the database before touching one.
///
/// # Errors
///
/// `401` no auth context; `403` any of FINAL-PLAN §6.6's four conditions;
/// `404` no such plan, or one the caller may not read; `409` a stale digest or a
/// plan that is not `previewed`/`approved`; `410` a plan older than the preview
/// TTL; `428` a plan that needs a second approver or an author-loss
/// acknowledgement; `500` a database fault.
#[cfg(feature = "db")]
pub async fn apply_plan(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(plan_id): Path<Uuid>,
    Json(body): Json<ApplyRequest>,
) -> Result<(axum::http::StatusCode, Json<DispatchResponse>), ApiError> {
    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let plan = load_plan_for_actor(&state, &viewer, plan_id).await?;
    let actor = require_plan_authority(&state, auth, plan.target_group_id).await?;

    refuse_if_expired(&plan)?;
    refuse_stale_digest(&plan, &body.plan_digest)?;

    if !matches!(plan.state.as_str(), "previewed" | "approved") {
        return Err(ApiError::Conflict {
            reason: format!(
                "a plan can only be applied from 'previewed' or 'approved'; this one is '{}'",
                plan.state
            ),
        });
    }

    // §6.5.5's refusal thresholds. A 428 and not a 403: the caller is
    // authorized, the plan is well-formed, and the missing thing is an approval
    // they can go and get. The threshold is restated from the same two numbers
    // `create_plan` uses to set `requires_second_approver`, so a preview that
    // says "you will need an approver" and an apply that demands one cannot
    // disagree.
    let needs_second = plan.item_count
        > i32::try_from(SECOND_APPROVER_ITEM_THRESHOLD).unwrap_or(i32::MAX)
        || plan.authors_losing_count > 0;
    if needs_second {
        match plan.approved_by {
            None => {
                return Err(ApiError::PreconditionRequired {
                    reason: "this plan needs a second instance admin, who must also administer \
                             the target group, to approve it before it can be applied"
                        .to_string(),
                })
            }
            Some(approver) if approver == plan.created_by => {
                return Err(ApiError::PreconditionRequired {
                    reason: "the recorded approver is the plan's own author; a different \
                             instance admin must approve"
                        .to_string(),
                })
            }
            Some(_) => {}
        }
    }
    // Unreachable while `create_plan` returns 501 for `mode='seal'`; written
    // because the acknowledgement is a property of the PLAN and the check
    // belongs with the other thresholds rather than arriving with PR-21.
    if plan.mode == "seal"
        && plan.authors_losing_count > 0
        && !(plan.acknowledge_author_loss || body.acknowledge_author_loss.unwrap_or(false))
    {
        return Err(ApiError::PreconditionRequired {
            reason: "this seal plan would cost authors access to their own claims; re-send with \
                     acknowledge_author_loss=true"
                .to_string(),
        });
    }

    dispatch(
        &state,
        &plan,
        actor,
        "applying",
        &["previewed".to_string(), "approved".to_string()],
        DispatchKind::Apply,
    )
    .await
}

/// `POST /api/v1/admin/privatization/plans/:id/abort` — stop a run in flight.
///
/// §6.5.5: "To stop: `POST …/abort` sets `state='failed'`; the applied prefix
/// stays applied. Then `POST …/revert` un-applies exactly the items with
/// `state='applied'`." So this is deliberately NOT an undo — it is a stop, and
/// the undo is a separate, audited, digest-echoing request.
///
/// The running handler re-reads the plan state at every batch boundary behind
/// the same global advisory lock, so an abort that commits here is seen by the
/// next batch and the run stops without writing a terminal state over it.
///
/// # Errors
///
/// `401` no auth context; `403` any of FINAL-PLAN §6.6's four conditions;
/// `404` no such plan, or one the caller may not read; `409` a plan that is not
/// running; `500` a database fault.
#[cfg(feature = "db")]
pub async fn abort_plan(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(plan_id): Path<Uuid>,
) -> Result<Json<PlanStateResponse>, ApiError> {
    use epigraph_db::repos::privatization::{PlanTransition, PrivatizationRepository};

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let plan = load_plan_for_actor(&state, &viewer, plan_id).await?;
    let actor = require_plan_authority(&state, auth, plan.target_group_id).await?;

    if !matches!(plan.state.as_str(), "applying" | "reverting") {
        return Err(ApiError::Conflict {
            reason: format!(
                "only a running plan can be aborted; this one is '{}'",
                plan.state
            ),
        });
    }

    let (mut maint, _bypass) = maintenance(&state).await?;
    let mut tx = sqlx::Connection::begin(&mut *maint)
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;
    let moved = PrivatizationRepository::transition_plan_conn(
        &mut tx,
        plan_id,
        PlanTransition::Finish {
            state: "failed",
            // NOT the empty list. The state check above read the plan before
            // this transaction opened, and the job handler's terminal write can
            // commit in between; an unconditional `failed` would stamp itself
            // over an `applied` that every item and every claim agree with, and
            // report a successful run as failed to `GET /plans/:id` and to the
            // audit timeline. `failed` is IN the list, so a double abort still
            // matches and stays idempotent rather than becoming a 409.
            from_states: &[
                "applying".to_string(),
                "reverting".to_string(),
                "failed".to_string(),
            ],
        },
    )
    .await
    .map_err(plan_write_error)?;
    if moved == 0 {
        // The transaction is dropped un-committed, so no `plan.abort` row is
        // written for an abort that aborted nothing.
        return Err(ApiError::Conflict {
            reason: "the plan reached a terminal state while it was being aborted; re-read it"
                .to_string(),
        });
    }
    PrivatizationRepository::record_plan_audit_conn(
        &mut tx,
        epigraph_db::repos::privatization::PlanAuditEntry {
            plan_id,
            actor_agent_id: actor,
            action: "plan.abort",
            kind: None,
            entity_id: None,
            plan_digest: plan.plan_digest.as_deref(),
            correlation_id: None,
        },
    )
    .await
    .map_err(plan_write_error)?;
    tx.commit()
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;

    Ok(Json(PlanStateResponse {
        plan_id,
        state: "failed".to_string(),
    }))
}

/// `POST /api/v1/admin/privatization/plans/:id/revert` — un-apply the items that
/// were applied.
///
/// # `restrict` is fully reversible, and clause 10 is now met in both arms
///
/// §6.5.5's strongest argument for `restrict` as the default is that `content`,
/// `content_tsv` and `embedding` are never touched, so a revert is a tenancy
/// UPDATE and nothing else. That half has shipped since the apply/revert slice.
///
/// FINAL-PLAN's acceptance clause 10 also asks that a `mode='seal'` plan whose
/// items are all unsealed can be reverted and one with sealed items returns
/// `409` with the still-sealed count. When this handler was written the
/// positive arm was unexercisable, because nothing in the product wrote a seal.
/// **PR-21 made it exercisable**: `seal-commit` writes the ciphertext row this
/// refusal reads, and `unseal-commit` removes it, so the 409 and its release
/// are now both reachable from the product's own surface.
///
/// # Errors
///
/// `401` no auth context; `403` any of FINAL-PLAN §6.6's four conditions;
/// `404` no such plan, or one the caller may not read; `409` a stale digest, a
/// plan that has not been applied, or one with sealed items; `500` a database
/// fault.
#[cfg(feature = "db")]
pub async fn revert_plan(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(plan_id): Path<Uuid>,
    Json(body): Json<RevertRequest>,
) -> Result<(axum::http::StatusCode, Json<DispatchResponse>), ApiError> {
    use epigraph_db::repos::privatization::PrivatizationRepository;

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let plan = load_plan_for_actor(&state, &viewer, plan_id).await?;
    let actor = require_plan_authority(&state, auth, plan.target_group_id).await?;

    // NO TTL CHECK. The 4 h window is on ACTING ON A PREVIEW, and a revert acts
    // on what was applied. A plan that can never be reverted after four hours is
    // not "fully reversible", which is the property §6.5.5 puts the most weight
    // on.
    refuse_stale_digest(&plan, &body.plan_digest)?;

    if !matches!(
        plan.state.as_str(),
        "applied" | "applied_with_drift" | "failed"
    ) {
        return Err(ApiError::Conflict {
            reason: format!(
                "only an applied or aborted plan can be reverted; this one is '{}'",
                plan.state
            ),
        });
    }

    // THE COUNT IS SCOPED TO SEAL-MODE PLANS, in the statement itself. That
    // matters here because `claim_encryption` belongs to the pre-existing
    // encrypted-subgraph feature, not to D4: a `restrict` plan whose frozen set
    // contains an already-encrypted claim sealed nothing, and refusing its
    // revert would defeat the full reversibility §6.5.4 leans on hardest.
    let (mut maint, _bypass) = maintenance(&state).await?;
    let sealed = PrivatizationRepository::sealed_item_count_conn(&mut maint, plan_id)
        .await
        .map_err(plan_write_error)?;
    drop(maint);
    if sealed > 0 {
        return Err(ApiError::Conflict {
            reason: format!(
                "{sealed} of this plan's items are still sealed; unseal them before reverting. \
                 A sealed claim cannot be made public — its content is ciphertext no reader is \
                 entitled to."
            ),
        });
    }

    dispatch(
        &state,
        &plan,
        actor,
        "reverting",
        &[
            "applied".to_string(),
            "applied_with_drift".to_string(),
            "failed".to_string(),
        ],
        DispatchKind::Revert,
    )
    .await
}

/// `GET /api/v1/admin/privatization/audit` — the privatization timeline.
///
/// # Why it is an HTTP route at all (§6.5.8)
///
/// The security critique proposed moving the instance-wide view to an
/// `epigraph_maintenance` CLI query. It was refused: that role bypasses RLS
/// entirely and writes no `security_events` row, so it would make the most
/// sensitive read in the system LESS controlled and LESS observable than the
/// route it replaced. An auditor gets plan-level rows for every plan they
/// administer, entity ids only where migration 083's policy admits the entity
/// arm, and **every read of this endpoint writes its own `security_events`
/// row**.
///
/// # It runs on the ACTOR's stamped connection, and that is the whole control
///
/// `privatization_audit` has no `visibility` column. Its tenancy is 083's
/// policy, resolved through a sub-select over `privatization_plans` that 087's
/// policy filters in turn — two policies deep, both properties of the
/// CONNECTION. Reusing the maintenance connection this handler also holds would
/// return every row in the instance and pass every test.
///
/// # Errors
///
/// `401` no auth context; `403` without the `instance:admin` scope; `500` a
/// database fault.
#[cfg(feature = "db")]
pub async fn get_audit(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<AuditResponse>, ApiError> {
    use epigraph_db::repos::privatization::{AuditQuery, PrivatizationRepository};
    use epigraph_db::repos::security_event::SecurityEventRepository;

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["instance:admin"])?;
    let Some(actor) = auth.agent_id else {
        return Err(ApiError::Unauthorized {
            reason: "this token carries no agent identity".to_string(),
        });
    };

    let limit = params.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);

    // THE AUDIT ROW IS WRITTEN BEFORE THE READ, not after. A reader who
    // disconnects mid-response, or a query that faults, has still made the
    // request; an audit trail that records only successful reads is one that
    // can be emptied by failing.
    //
    // `success` is therefore `None` and not `true`. At this point the read has
    // not happened, and a hardcoded `true` would make the column carry no
    // information at all for this event type. `Option<bool>` already has a value
    // for "attempted, outcome not yet known".
    {
        let (mut maint, _bypass) = maintenance(&state).await?;
        SecurityEventRepository::log_conn(
            &mut maint,
            &epigraph_db::repos::security_event::SecurityEventRow {
                id: Uuid::new_v4(),
                event_type: AUDIT_READ_EVENT_TYPE.to_string(),
                agent_id: Some(actor),
                success: None,
                details: serde_json::json!({
                    "plan_id": params.plan_id,
                    "entity_id": params.entity_id,
                    "limit": limit,
                }),
                ip_address: None,
                user_agent: None,
                correlation_id: Some(new_correlation_id()),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .map_err(plan_write_error)?;
    }

    let mut read = state.read_as(&viewer).await.map_err(scoped_read_error)?;
    let rows = PrivatizationRepository::load_audit_conn(
        &mut read,
        AuditQuery {
            plan_id: params.plan_id,
            entity_id: params.entity_id,
            since: params.since,
            limit,
        },
    )
    .await?;
    read.commit().await.map_err(scoped_read_error)?;

    Ok(Json(AuditResponse {
        events: rows
            .into_iter()
            .map(|r| AuditEvent {
                id: r.id,
                plan_id: r.plan_id,
                actor_agent_id: r.actor_agent_id,
                action: r.action,
                kind: r.kind,
                entity_id: r.entity_id,
                before_visibility: r.before_visibility,
                after_visibility: r.after_visibility,
                correlation_id: r.correlation_id,
                created_at: r.created_at,
            })
            .collect(),
    }))
}

// =============================================================================
// SEAL — the two-phase, client-driven ceremony (FINAL-PLAN §6.5.6)
// =============================================================================

/// `GET /api/v1/admin/privatization/plans/:id/seal-manifest`.
///
/// # THE ONLY RESPONSE IN THE SYSTEM THAT RETURNS PLAINTEXT THE CALLER MAY NOT
/// OTHERWISE READ
///
/// §6.5.6 step 1 says so and this handler is where that is true. It is
/// deliberately NOT viewer-filtered: a manifest narrowed to what the actor can
/// read produces a commit covering a subset of the §6.5.4 TCB, and a partial
/// seal reports success while the plaintext is one `pg_dump` away. What stands
/// in for the filter is everything else — §6.6's three conditions, a plan the
/// caller administers, `mode='seal'`, a plan that has already been APPLIED (so
/// every row is already `visibility='group'`), and a dual entry in
/// `security_events` and `privatization_audit` for every page served.
///
/// # `manifest_digest` binds the SHAPE, not the bytes
///
/// It is BLAKE3 over the page's `(claim_id, version ids…, evidence ids…)` in
/// order. Seal-commit recomputes it from the DATABASE at commit time, so a
/// version or evidence row inserted between the manifest and the commit changes
/// the digest and the commit is refused. A digest over the plaintext would
/// prove only that the client echoed what it was sent, which is the property
/// that matters least.
///
/// # Errors
///
/// `401` no auth context; `403` §6.6; `404` no such plan, or one the caller may
/// not read; `409` a plan that is not `mode='seal'` or has not been applied;
/// `410` an expired plan; `500` a database fault.
#[cfg(feature = "db")]
pub async fn seal_manifest(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(plan_id): Path<Uuid>,
    Query(params): Query<ManifestQuery>,
) -> Result<Json<SealManifest>, ApiError> {
    use epigraph_db::repos::privatization::PrivatizationRepository;

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let plan = load_plan_for_actor(&state, &viewer, plan_id).await?;
    let actor = require_plan_authority(&state, auth, plan.target_group_id).await?;
    refuse_if_expired(&plan)?;
    refuse_unless_sealable(&plan)?;

    let limit = manifest_limit(params.limit)?;
    let (mut maint, bypass) = maintenance(&state).await?;

    let epoch = PrivatizationRepository::active_epoch_conn(&mut maint, plan.target_group_id)
        .await?
        .ok_or_else(|| ApiError::Conflict {
            reason: "the target group has no active key epoch; rotate a key into it before \
                     sealing"
                .to_string(),
        })?;

    let items = PrivatizationRepository::seal_manifest_page_conn(
        &mut maint,
        &bypass,
        plan_id,
        params.cursor,
        limit,
    )
    .await?;

    let digest = manifest_digest(items.iter().map(|i| {
        (
            i.claim_id,
            i.versions.iter().map(|v| v.id).collect::<Vec<_>>(),
            i.evidence.iter().map(|e| e.id).collect::<Vec<_>>(),
        )
    }));
    let next_cursor = items.last().map(|i| i.claim_id);

    // RETURNED BEFORE THE AUDIT ACQUIRES ITS OWN. `log_manifest_read` takes a
    // maintenance connection, and the maintenance pool is deliberately the
    // smallest in the process — `load_plan_for_actor` makes the same commit for
    // the same reason. Two concurrent manifest requests each holding one and
    // blocking on a second is a deadlock the pool size makes reachable.
    drop(bypass);
    drop(maint);

    // DUAL-LOGGED, and BEFORE the body is returned. `security_events` is the
    // principal-keyed record that this agent was served plaintext;
    // `privatization_audit` is the plan-keyed one a group admin can read. §6.5.6
    // requires both, and neither is a substitute for the other. The `?` is what
    // makes it fail CLOSED: an audit that cannot be written means no plaintext
    // leaves this process.
    log_manifest_read(
        &state,
        &plan,
        actor,
        "plan.seal_manifest",
        items.len(),
        &digest,
    )
    .await?;

    Ok(Json(SealManifest {
        plan_id,
        epoch,
        pad_to: plan.pad_to,
        manifest_digest: digest,
        next_cursor,
        items: items
            .into_iter()
            .map(|i| SealManifestEntry {
                claim_id: i.claim_id,
                content: i.content,
                labels: i.labels,
                properties: i.properties,
                versions: i
                    .versions
                    .into_iter()
                    .map(|v| ManifestVersion {
                        id: v.id,
                        content: v.content,
                    })
                    .collect(),
                evidence: i
                    .evidence
                    .into_iter()
                    .map(|e| ManifestEvidence {
                        id: e.id,
                        raw_content: e.raw_content,
                        properties: e.properties,
                    })
                    .collect(),
            })
            .collect(),
    }))
}

/// `POST /api/v1/admin/privatization/plans/:id/seal-commit`.
///
/// # A commit missing any TCB member is REFUSED, not partially applied
///
/// The verification list is §6.5.6's, in order, and every one of them refuses
/// the WHOLE request rather than the offending item. A per-item rejection would
/// produce exactly the state §6.5.4 indicts: some claims sealed, some not, the
/// operator told it worked.
///
/// # Errors
///
/// `400` a malformed ciphertext, a wrong hash, a padding violation, or a
/// missing TCB member; `401` no auth context; `403` §6.6; `404` no such plan;
/// `409` a plan that is not sealable or a stale manifest digest; `410` an
/// expired plan; `500` a database fault.
#[cfg(feature = "db")]
#[allow(clippy::too_many_lines)]
pub async fn seal_commit(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(plan_id): Path<Uuid>,
    Json(body): Json<SealCommitRequest>,
) -> Result<Json<CommitResponse>, ApiError> {
    use epigraph_db::repos::privatization::{
        PrivatizationRepository, SealCommitEvidence, SealCommitItem, SealCommitVersion,
    };

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let plan = load_plan_for_actor(&state, &viewer, plan_id).await?;
    let actor = require_plan_authority(&state, auth, plan.target_group_id).await?;
    refuse_if_expired(&plan)?;
    refuse_unless_sealable(&plan)?;

    if body.items.is_empty() {
        return Err(ApiError::BadRequest {
            message: "a seal-commit with no items is not a seal".to_string(),
        });
    }

    let (mut maint, _bypass) = maintenance(&state).await?;

    let epoch = PrivatizationRepository::active_epoch_conn(&mut maint, plan.target_group_id)
        .await?
        .ok_or_else(|| ApiError::Conflict {
            reason: "the target group has no active key epoch; rotate a key into it before \
                     sealing"
                .to_string(),
        })?;

    // 1. Every claim_id is in the plan's FROZEN item set. Not "exists" — in the
    //    plan. A commit naming a claim outside the plan would seal a row nobody
    //    approved.
    let claim_ids: Vec<Uuid> = body.items.iter().map(|i| i.claim_id).collect();
    let frozen =
        PrivatizationRepository::plan_contains_conn(&mut maint, plan_id, &claim_ids).await?;
    if frozen.len() != claim_ids.len() {
        return Err(ApiError::BadRequest {
            message: format!(
                "{} of {} claims in this commit are not items of plan {plan_id}",
                claim_ids.len() - frozen.len(),
                claim_ids.len()
            ),
        });
    }

    // 2. The TCB shape, read from the DATABASE and not from the manifest this
    //    server served. That is the whole point of re-reading it: a version row
    //    inserted since would otherwise keep its plaintext.
    let shape = PrivatizationRepository::seal_tcb_shape_conn(&mut maint, &claim_ids).await?;

    // 3. The manifest digest, recomputed over that shape in the same order the
    //    manifest served it.
    let expected = manifest_digest(
        shape
            .iter()
            .map(|s| (s.claim_id, s.version_ids.clone(), s.evidence_ids.clone())),
    );
    if expected != body.manifest_digest {
        return Err(ApiError::Conflict {
            reason: "the manifest digest does not describe this plan's current TCB; a version or \
                     evidence row changed since the manifest was served. Re-read the manifest and \
                     re-commit"
                .to_string(),
        });
    }

    // 4. Every TCB member is covered, and every ciphertext parses, hashes and
    //    pads correctly.
    let mut items: Vec<SealCommitItem> = Vec::with_capacity(body.items.len());
    for item in &body.items {
        let s = shape
            .iter()
            .find(|s| s.claim_id == item.claim_id)
            .ok_or_else(|| ApiError::BadRequest {
                message: format!("claim {} has no rows to seal", item.claim_id),
            })?;

        let content_ct = decode_ciphertext(&item.content_ct_b64, "content", plan.pad_to)?;
        let labels_ct = decode_ciphertext(&item.labels_ct_b64, "labels", plan.pad_to)?;
        let properties_ct = decode_ciphertext(&item.properties_ct_b64, "properties", plan.pad_to)?;

        let content_hash = decode_hash(&item.content_hash_b64)?;
        if content_hash != blake3::hash(&content_ct).as_bytes() {
            return Err(ApiError::BadRequest {
                message: format!(
                    "content_hash for claim {} is not BLAKE3 over the content ciphertext",
                    item.claim_id
                ),
            });
        }

        let mut versions = Vec::with_capacity(item.versions.len());
        for v in &item.versions {
            versions.push(SealCommitVersion {
                id: v.id,
                content_ct: decode_ciphertext(&v.ct_b64, "version content", plan.pad_to)?,
            });
        }
        require_full_cover(
            item.claim_id,
            "claim_versions",
            &s.version_ids,
            &versions.iter().map(|v| v.id).collect::<Vec<_>>(),
        )?;

        let mut evidence = Vec::with_capacity(item.evidence.len());
        for e in &item.evidence {
            evidence.push(SealCommitEvidence {
                id: e.id,
                content_ct: decode_ciphertext(&e.ct_b64, "evidence content", plan.pad_to)?,
                properties_ct: decode_ciphertext(
                    &e.props_ct_b64,
                    "evidence properties",
                    plan.pad_to,
                )?,
            });
        }
        require_full_cover(
            item.claim_id,
            "evidence",
            &s.evidence_ids,
            &evidence.iter().map(|e| e.id).collect::<Vec<_>>(),
        )?;

        items.push(SealCommitItem {
            claim_id: item.claim_id,
            content_ct,
            labels_ct,
            properties_ct,
            content_hash,
            versions,
            evidence,
        });
    }

    // 5. The mutation. One transaction, under the global privatization advisory
    //    lock, so a seal-commit and an apply batch cannot interleave over the
    //    same rows. One correlation id for the whole request — see
    //    `unseal_commit` — so the audit rows and the reseal job it dispatches
    //    carry the same one rather than two unrelated ones.
    let correlation_id = new_correlation_id();
    let mut tx = sqlx::Connection::begin(&mut *maint)
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;
    PrivatizationRepository::begin_batch_conn(&mut tx)
        .await
        .map_err(plan_write_error)?;
    let sealed =
        PrivatizationRepository::seal_claims_conn(&mut tx, plan.target_group_id, epoch, &items)
            .await
            .map_err(plan_write_error)?;
    PrivatizationRepository::record_seal_audit_conn(
        &mut tx,
        plan_id,
        actor,
        "item.seal",
        &sealed,
        true,
        Some(&correlation_id),
    )
    .await
    .map_err(plan_write_error)?;

    // A re-seal after a key rotation is a seal-commit like any other, and this
    // is the moment "the last row moves" (§6.7 point 3). Enqueueing the check
    // here — in the same transaction as the mutation, on the maintenance
    // connection migration 077's `jobs_app` policy requires — is what lets
    // `PrivatizationResealHandler` be the only writer that clears
    // `groups.reseal_required_at` without polling for it.
    if !sealed.is_empty() {
        let job = epigraph_jobs::EpiGraphJob::PrivatizationReseal {
            group_id: plan.target_group_id,
            dispatched_by: actor,
            correlation_id: correlation_id.clone(),
        };
        let payload = serde_json::to_value(&job).map_err(|e| {
            tracing::error!(target: "tenancy.privatization", error = %e, "reseal job payload");
            ApiError::InternalError {
                message: "Failed to encode the reseal check job".to_string(),
            }
        })?;
        PrivatizationRepository::enqueue_job_conn(&mut tx, job.job_type(), &payload)
            .await
            .map_err(plan_write_error)?;
    }

    tx.commit()
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;

    let committed = sealed.len();
    Ok(Json(CommitResponse {
        plan_id,
        committed,
        // Items whose ciphertext row already existed. NOT a failure — a
        // re-delivered commit is a no-op — but reported so a client that
        // expected to seal them knows it did not.
        already_done: body.items.len() - committed,
    }))
}

/// `GET /api/v1/admin/privatization/plans/:id/unseal-manifest`.
///
/// Ciphertext only, so unlike its seal counterpart it discloses no plaintext.
/// It is still §6.6-gated and still audited: which claims are sealed is itself
/// information about a group's private region.
///
/// # Errors
///
/// `401` no auth context; `403` §6.6; `404` no such plan; `500` a database
/// fault.
#[cfg(feature = "db")]
pub async fn unseal_manifest(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(plan_id): Path<Uuid>,
    Query(params): Query<ManifestQuery>,
) -> Result<Json<UnsealManifest>, ApiError> {
    use base64::Engine as _;
    use epigraph_db::repos::privatization::PrivatizationRepository;

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let plan = load_plan_for_actor(&state, &viewer, plan_id).await?;
    let actor = require_plan_authority(&state, auth, plan.target_group_id).await?;
    // NOT `refuse_if_expired`. Unsealing is the way BACK, and a plan whose
    // preview has gone stale is exactly the plan an operator most needs to
    // undo — the same argument `revert_plan` makes for skipping the TTL.
    if plan.mode != "seal" {
        return Err(ApiError::Conflict {
            reason: format!("plan {plan_id} is mode='{}', not 'seal'", plan.mode),
        });
    }

    let limit = manifest_limit(params.limit)?;
    let (mut maint, _bypass) = maintenance(&state).await?;
    let items = PrivatizationRepository::unseal_manifest_page_conn(
        &mut maint,
        plan_id,
        params.cursor,
        limit,
    )
    .await?;

    let digest = manifest_digest(items.iter().map(|i| {
        (
            i.claim_id,
            i.versions.iter().map(|v| v.id).collect::<Vec<_>>(),
            i.evidence.iter().map(|e| e.id).collect::<Vec<_>>(),
        )
    }));
    let next_cursor = items.last().map(|i| i.claim_id);
    // See `seal_manifest`: the maintenance connection goes back to the pool
    // before the audit acquires its own.
    drop(maint);
    log_manifest_read(
        &state,
        &plan,
        actor,
        "plan.unseal_manifest",
        items.len(),
        &digest,
    )
    .await?;

    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(Json(UnsealManifest {
        plan_id,
        manifest_digest: digest,
        next_cursor,
        items: items
            .into_iter()
            .map(|i| UnsealManifestEntry {
                claim_id: i.claim_id,
                epoch: i.epoch,
                pad_to: plan.pad_to,
                content_ct_b64: b64.encode(&i.content_ct),
                labels_ct_b64: i.labels_ct.as_ref().map(|c| b64.encode(c)),
                properties_ct_b64: i.properties_ct.as_ref().map(|c| b64.encode(c)),
                versions: i
                    .versions
                    .into_iter()
                    .map(|v| CommitVersion {
                        id: v.id,
                        ct_b64: b64.encode(&v.content_ct),
                    })
                    .collect(),
                evidence: i
                    .evidence
                    .into_iter()
                    .map(|e| CommitEvidence {
                        id: e.id,
                        ct_b64: b64.encode(&e.content_ct),
                        props_ct_b64: b64.encode(&e.properties_ct),
                    })
                    .collect(),
            })
            .collect(),
    }))
}

/// `POST /api/v1/admin/privatization/plans/:id/unseal-commit`.
///
/// # It enqueues an embedding job per restored claim, and that is ops F14
///
/// The seal destroyed the vector; unseal cannot recreate it, and
/// `find_claims_needing_embeddings` is `ORDER BY created_at LIMIT $1` with no
/// priority, so a freshly unsealed 2019 claim would queue behind every other
/// embedding-less row. The job is enqueued in the SAME transaction as the
/// restore, on the maintenance connection, because migration 077's `jobs_app`
/// policy is what stops anything else enqueueing privatization work and the
/// restore and its follow-up must not be able to disagree.
///
/// # It is scoped to the plan, exactly as `seal-commit` is
///
/// §6.6's authority is checked against `plan.target_group_id`, so the set of
/// rows the request may MUTATE has to be the set that authority was granted
/// over. Three checks establish that, and none of them is redundant:
///
/// 1. `plan_contains_conn` — every `claim_id` in the body is a FROZEN item of
///    this plan. Without it the authorisation is evaluated against one object
///    and applied to another, caller-chosen one.
/// 2. `unseal_tcb_shape_conn`, which reads only ciphertext rows bound to
///    `plan.target_group_id`, and a `ce.group_id` predicate inside the mutation.
///    A claim can be an item of one group's plan while its ciphertext belongs to
///    another group's key; plan membership alone does not answer that.
/// 3. `require_full_cover` over that shape, so a commit that restores a claim's
///    head while omitting one of its version or evidence rows is refused whole.
///    The seal destroyed the plaintext, so an uncovered ciphertext row deleted
///    here would be unrecoverable by anyone.
///
/// The body's `content_hash` is NOT one of those checks and cannot be: it is
/// BLAKE3 over the caller's own supplied plaintext, self-consistent by
/// construction, and the server holds no key with which to check the plaintext
/// against the ciphertext it stored. That is precisely why the scoping
/// predicates carry the whole weight.
///
/// **One job per CLAIM and not per evidence row.**
/// `EpiGraphJob::EmbeddingGeneration` carries `claim_id` only, and
/// `privatization_plan_items` has no evidence-kinded row for a per-evidence job
/// to name. The evidence half of ops F14 is therefore deferred, with an owner,
/// rather than silently reported as done. It is a functional gap and not a
/// confidentiality one — the seal nulled the vector, which is the safe
/// direction.
///
/// # Errors
///
/// `400` a hash mismatch, empty content, a claim outside the plan or an
/// incomplete cover; `401` no auth context; `403` §6.6; `404` no such plan;
/// `409` a plan that is not `mode='seal'` or is in a state no ceremony runs in;
/// `500` a database fault.
#[cfg(feature = "db")]
pub async fn unseal_commit(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(plan_id): Path<Uuid>,
    Json(body): Json<UnsealCommitRequest>,
) -> Result<Json<CommitResponse>, ApiError> {
    use epigraph_db::repos::privatization::{
        PrivatizationRepository, UnsealCommitEvidence, UnsealCommitItem, UnsealCommitVersion,
    };

    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };

    let plan = load_plan_for_actor(&state, &viewer, plan_id).await?;
    let actor = require_plan_authority(&state, auth, plan.target_group_id).await?;
    if plan.mode != "seal" {
        return Err(ApiError::Conflict {
            reason: format!("plan {plan_id} is mode='{}', not 'seal'", plan.mode),
        });
    }
    // NOT `refuse_unless_sealable`, and NOT `refuse_if_expired`. Unsealing is
    // the way BACK: it must still work while a revert is in flight, which is the
    // one state `refuse_unless_sealable` forbids and the one in which an
    // operator most needs it, and `unseal_manifest` already argues why the 4h
    // TTL does not apply to the reverse direction. What is checked is that the
    // plan reached a state in which a seal ceremony could have run at all — a
    // `previewed` or `approved` plan has sealed nothing, so a commit against it
    // is naming rows some other ceremony sealed.
    if !matches!(
        plan.state.as_str(),
        "applied" | "applied_with_drift" | "reverting"
    ) {
        return Err(ApiError::Conflict {
            reason: format!(
                "plan {plan_id} is '{}'; an unseal ceremony runs only against a plan that was \
                 applied",
                plan.state
            ),
        });
    }
    if body.items.is_empty() {
        return Err(ApiError::BadRequest {
            message: "an unseal-commit with no items is not an unseal".to_string(),
        });
    }

    let (mut maint, _bypass) = maintenance(&state).await?;

    // 1. Every claim_id is a FROZEN item of this plan. The mirror of
    //    `seal_commit` step 1, and for the same reason read in the other
    //    direction: §6.6 authorised this actor over `plan.target_group_id`, so a
    //    commit naming a claim outside the plan would spend that authority on a
    //    row nobody approved — writing caller-supplied plaintext into it and
    //    deleting the ciphertext that was the only remaining copy.
    let claim_ids: Vec<Uuid> = body.items.iter().map(|i| i.claim_id).collect();
    let frozen =
        PrivatizationRepository::plan_contains_conn(&mut maint, plan_id, &claim_ids).await?;
    if frozen.len() != claim_ids.len() {
        return Err(ApiError::BadRequest {
            message: format!(
                "{} of {} claims in this commit are not items of plan {plan_id}",
                claim_ids.len() - frozen.len(),
                claim_ids.len()
            ),
        });
    }

    // 2. The ciphertext shape, read from the DATABASE and bound to this plan's
    //    target group. A claim that is absent from it carries no ciphertext for
    //    this group and is a no-op below, which is what makes a re-delivered
    //    commit succeed rather than trip the cover check.
    let shape = PrivatizationRepository::unseal_tcb_shape_conn(
        &mut maint,
        plan.target_group_id,
        &claim_ids,
    )
    .await?;

    let mut items: Vec<UnsealCommitItem> = Vec::with_capacity(body.items.len());
    for item in &body.items {
        // `claims_content_not_empty` would refuse this at the database with a
        // 23514; refusing it here makes it a 400 with a sentence, and keeps an
        // empty restore from being the thing that rolls back a whole batch.
        if item.content.trim().is_empty() {
            return Err(ApiError::BadRequest {
                message: format!(
                    "the restored content for claim {} is empty; claims_content_not_empty \
                     forbids it and an empty restore is indistinguishable from a lost plaintext",
                    item.claim_id
                ),
            });
        }
        let content_hash = decode_hash(&item.content_hash_b64)?;
        if content_hash != blake3::hash(item.content.as_bytes()).as_bytes() {
            return Err(ApiError::BadRequest {
                message: format!(
                    "content_hash for claim {} is not BLAKE3 over the restored plaintext",
                    item.claim_id
                ),
            });
        }
        // 3. Cover. Only for a claim that IS sealed under this group: one that is
        //    absent from `shape` has no ciphertext left to strand, and demanding
        //    an empty cover from it would turn every re-delivered commit into a
        //    400.
        if let Some(s) = shape.iter().find(|s| s.claim_id == item.claim_id) {
            require_full_cover(
                item.claim_id,
                "claim_version_encryption",
                &s.version_ids,
                &item.versions.iter().map(|v| v.id).collect::<Vec<_>>(),
            )?;
            require_full_cover(
                item.claim_id,
                "evidence_encryption",
                &s.evidence_ids,
                &item.evidence.iter().map(|e| e.id).collect::<Vec<_>>(),
            )?;
        }

        items.push(UnsealCommitItem {
            claim_id: item.claim_id,
            content: item.content.clone(),
            content_hash,
            labels: item.labels.clone(),
            properties: item.properties.clone(),
            versions: item
                .versions
                .iter()
                .map(|v| UnsealCommitVersion {
                    id: v.id,
                    content: v.content.clone(),
                })
                .collect(),
            evidence: item
                .evidence
                .iter()
                .map(|e| UnsealCommitEvidence {
                    id: e.id,
                    raw_content: e.raw_content.clone(),
                    properties: e.properties.clone(),
                })
                .collect(),
        });
    }

    // ONE correlation id for the whole request, threaded into both the audit
    // rows and the follow-up job, so a ceremony can be reassembled from either
    // end. The audit rows are the surface a group admin reads back to see what
    // an unseal did, and a NULL there makes them unjoinable to everything else
    // the same request wrote.
    let correlation_id = new_correlation_id();
    let mut tx = sqlx::Connection::begin(&mut *maint)
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;
    PrivatizationRepository::begin_batch_conn(&mut tx)
        .await
        .map_err(plan_write_error)?;
    let restored =
        PrivatizationRepository::unseal_claims_conn(&mut tx, plan.target_group_id, &items)
            .await
            .map_err(plan_write_error)?;

    for claim_id in &restored {
        let job = epigraph_jobs::EpiGraphJob::EmbeddingGeneration {
            claim_id: *claim_id,
        };
        let payload = serde_json::to_value(&job).map_err(|e| {
            tracing::error!(target: "tenancy.privatization", error = %e, "embedding job payload");
            ApiError::InternalError {
                message: "Failed to encode the re-embedding job".to_string(),
            }
        })?;
        PrivatizationRepository::enqueue_job_conn(&mut tx, job.job_type(), &payload)
            .await
            .map_err(plan_write_error)?;
    }

    // Unsealing is the OTHER way a group answers a rotation: a claim whose
    // ciphertext row is gone is not a row still bound to a retired epoch. Without
    // this enqueue the only producer of the check is `seal_commit`, so a group
    // that unseals everything rather than re-sealing it keeps
    // `reseal_required_at` set forever with nothing able to observe that the
    // stale count reached zero. The handler is idempotent and does no
    // cryptography, so enqueueing it is cheap and re-enqueueing it is harmless.
    if !restored.is_empty() {
        let job = epigraph_jobs::EpiGraphJob::PrivatizationReseal {
            group_id: plan.target_group_id,
            dispatched_by: actor,
            correlation_id: correlation_id.clone(),
        };
        let payload = serde_json::to_value(&job).map_err(|e| {
            tracing::error!(target: "tenancy.privatization", error = %e, "reseal job payload");
            ApiError::InternalError {
                message: "Failed to encode the reseal check job".to_string(),
            }
        })?;
        PrivatizationRepository::enqueue_job_conn(&mut tx, job.job_type(), &payload)
            .await
            .map_err(plan_write_error)?;
    }

    PrivatizationRepository::record_seal_audit_conn(
        &mut tx,
        plan_id,
        actor,
        "item.unseal",
        &restored,
        false,
        Some(&correlation_id),
    )
    .await
    .map_err(plan_write_error)?;
    tx.commit()
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;

    let committed = restored.len();
    Ok(Json(CommitResponse {
        plan_id,
        committed,
        already_done: items.len() - committed,
    }))
}

// =============================================================================
// HELPERS (db feature)
// =============================================================================

/// Refuse a plan that cannot be sealed yet.
///
/// Two conditions, and the second is the ordering invariant: §6.5.5 says
/// "restrict first, then seal", and migration 081's
/// `claim_encryption_no_public_sealed` raises `42501` if it is not honoured.
/// Catching it here makes it a 409 with a sentence rather than a 500 carrying a
/// SQLSTATE.
#[cfg(feature = "db")]
fn refuse_unless_sealable(
    plan: &epigraph_db::repos::privatization::PlanRow,
) -> Result<(), ApiError> {
    if plan.mode != "seal" {
        return Err(ApiError::Conflict {
            reason: format!(
                "plan {} is mode='{}'; only a seal plan has a manifest",
                plan.id, plan.mode
            ),
        });
    }
    if !matches!(plan.state.as_str(), "applied" | "applied_with_drift") {
        return Err(ApiError::Conflict {
            reason: format!(
                "plan {} is '{}'; a seal ceremony runs only after the plan has been applied, \
                 because a claim that is still public cannot be sealed",
                plan.id, plan.state
            ),
        });
    }
    Ok(())
}

/// The manifest page size: default 500, ceiling 500 (§6.5.6).
#[cfg(feature = "db")]
fn manifest_limit(requested: Option<i64>) -> Result<i64, ApiError> {
    const MAX: i64 = 500;
    match requested {
        None => Ok(MAX),
        Some(n) if (1..=MAX).contains(&n) => Ok(n),
        Some(n) => Err(ApiError::BadRequest {
            message: format!("limit must be between 1 and {MAX}, got {n}"),
        }),
    }
}

/// BLAKE3 over a page's `(claim_id, version ids…, evidence ids…)`, `b3:` + hex.
///
/// The SHAPE of the TCB, not its bytes. Recomputable from the database at
/// commit time, which is what lets seal-commit notice a version or evidence row
/// that appeared after the manifest was served.
#[cfg(feature = "db")]
fn manifest_digest(items: impl Iterator<Item = (Uuid, Vec<Uuid>, Vec<Uuid>)>) -> String {
    let mut hasher = blake3::Hasher::new();
    for (claim_id, mut versions, mut evidence) in items {
        hasher.update(claim_id.as_bytes());
        versions.sort_unstable();
        evidence.sort_unstable();
        hasher.update(b"v");
        for v in versions {
            hasher.update(v.as_bytes());
        }
        hasher.update(b"e");
        for e in evidence {
            hasher.update(e.as_bytes());
        }
    }
    format!("b3:{}", hex::encode(hasher.finalize().as_bytes()))
}

/// Decode one base64 ciphertext and run §6.5.6's three checks on it.
///
/// `EncryptedPayload::from_bytes` carries the `>= 28 bytes` and `<= 10 MiB`
/// guards; the modulus is this function's. The server can check the modulus and
/// nothing else about the padding, because it never sees a plaintext — which is
/// why the padding target is the STORED BLOB rather than the plaintext. See
/// `epigraph_privacy::padding`.
#[cfg(feature = "db")]
fn decode_ciphertext(b64: &str, field: &str, pad_to: i32) -> Result<Vec<u8>, ApiError> {
    use base64::Engine as _;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| ApiError::BadRequest {
            message: format!("{field} ciphertext is not valid base64: {e}"),
        })?;
    epigraph_crypto::EncryptedPayload::from_bytes(&bytes).map_err(|e| ApiError::BadRequest {
        message: format!("{field} ciphertext is not a well-formed encrypted payload: {e}"),
    })?;
    if pad_to > 0 {
        let modulus = usize::try_from(pad_to).unwrap_or(1);
        if bytes.len() % modulus != 0 {
            return Err(ApiError::BadRequest {
                message: format!(
                    "{field} ciphertext is {} bytes, which is not a multiple of this plan's \
                     pad_to={pad_to}. Length padding is what stops a stored ciphertext length \
                     from being a function of its plaintext length",
                    bytes.len()
                ),
            });
        }
    }
    Ok(bytes)
}

/// Decode a base64 BLAKE3 digest, refusing anything that is not 32 bytes.
///
/// `claims_content_hash_length` pins the column to exactly 32; catching it here
/// makes a wrong length a 400 rather than a 500 carrying `23514`.
#[cfg(feature = "db")]
fn decode_hash(b64: &str) -> Result<Vec<u8>, ApiError> {
    use base64::Engine as _;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| ApiError::BadRequest {
            message: format!("content_hash is not valid base64: {e}"),
        })?;
    if bytes.len() != 32 {
        return Err(ApiError::BadRequest {
            message: format!("content_hash must be 32 bytes, got {}", bytes.len()),
        });
    }
    Ok(bytes)
}

/// Refuse unless `supplied` covers every id in `required`.
///
/// The all-or-nothing rule, per table. It refuses on a MISSING id and tolerates
/// an extra one only in the sense that the length check catches it: a commit
/// naming a row that is not in the shape has already failed the digest.
#[cfg(feature = "db")]
fn require_full_cover(
    claim_id: Uuid,
    table: &str,
    required: &[Uuid],
    supplied: &[Uuid],
) -> Result<(), ApiError> {
    let have: std::collections::BTreeSet<Uuid> = supplied.iter().copied().collect();
    let missing: Vec<Uuid> = required
        .iter()
        .copied()
        .filter(|id| !have.contains(id))
        .collect();
    if missing.is_empty() && have.len() == required.len() {
        return Ok(());
    }
    Err(ApiError::BadRequest {
        message: format!(
            "the commit for claim {claim_id} covers {} of {} {table} rows. FINAL-PLAN §6.5.4's \
             TCB is a set: a commit missing any member is refused, not partially applied",
            have.len(),
            required.len()
        ),
    })
}

/// Write the dual log §6.5.6 requires for a manifest read.
///
/// `security_events` is principal-keyed and records that THIS agent was served
/// the page; `privatization_audit` is plan-keyed and is what a group admin can
/// read back. Neither substitutes for the other, and the entity ids stay out of
/// `security_events` for the reason `dispatch` gives: its policy is keyed on the
/// principal, not on the target group.
#[cfg(feature = "db")]
async fn log_manifest_read(
    state: &AppState,
    plan: &epigraph_db::repos::privatization::PlanRow,
    actor: Uuid,
    action: &str,
    served: usize,
    digest: &str,
) -> Result<(), ApiError> {
    use epigraph_db::repos::privatization::{PlanAuditEntry, PrivatizationRepository};
    use epigraph_db::repos::security_event::{SecurityEventRepository, SecurityEventRow};

    let correlation_id = new_correlation_id();
    let (mut maint, _bypass) = maintenance(state).await?;
    let mut tx = sqlx::Connection::begin(&mut *maint)
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;

    SecurityEventRepository::log_conn(
        &mut tx,
        &SecurityEventRow {
            id: Uuid::new_v4(),
            event_type: action.to_string(),
            agent_id: Some(actor),
            success: Some(true),
            details: serde_json::json!({
                "plan_id": plan.id,
                "target_group_id": plan.target_group_id,
                "items_served": served,
                "manifest_digest": digest,
            }),
            ip_address: None,
            user_agent: None,
            correlation_id: Some(correlation_id.clone()),
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .map_err(plan_write_error)?;

    PrivatizationRepository::record_plan_audit_conn(
        &mut tx,
        PlanAuditEntry {
            plan_id: plan.id,
            actor_agent_id: actor,
            action,
            kind: None,
            entity_id: None,
            plan_digest: plan.plan_digest.as_deref(),
            correlation_id: Some(&correlation_id),
        },
    )
    .await
    .map_err(plan_write_error)?;

    tx.commit()
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))
}

/// Re-run FINAL-PLAN §6.6's four conditions against a plan's own target group.
///
/// Takes its own maintenance connection for the reason
/// `require_instance_admin_for_group`'s doc gives: the plurality and role checks
/// count `group_memberships` rows, which migration 077's policy narrows on the
/// actor's connection.
///
/// Returns the caller's `agent_id`, so a handler that needs to attribute a write
/// cannot proceed with `None` and cannot re-derive it from a different source.
#[cfg(feature = "db")]
async fn require_plan_authority(
    state: &AppState,
    auth: &crate::middleware::bearer::AuthContext,
    target_group_id: Uuid,
) -> Result<Uuid, ApiError> {
    let (mut maint, _bypass) = maintenance(state).await?;
    crate::middleware::instance_authz::require_instance_admin_for_group(
        auth,
        target_group_id,
        &mut maint,
    )
    .await
}

/// The maintenance connection, with the one reason this surface grants a bypass
/// under.
///
/// `SystemReason::PrivatizationSelection` is used for the authority check, the
/// selection, the state flips and the enqueue alike. It is not stretched: the
/// reason space is a CLOSED, monotonically decreasing register
/// (`viewer_ratchet.rs` asserts `SystemReason::ALL.len()` never grows), and the
/// question every one of those statements answers is the same one — "may this
/// operator privatize this group's subgraph". The apply-side reason,
/// `SystemReason::PrivatizationApply`, belongs to the JOB, which is where the
/// rows actually move.
#[cfg(feature = "db")]
async fn maintenance(
    state: &AppState,
) -> Result<
    (
        epigraph_db::MaintenanceConn<'_>,
        epigraph_db::visibility::Viewer,
    ),
    ApiError,
> {
    use epigraph_db::visibility::SystemReason;

    state
        .maintenance_viewer(SystemReason::PrivatizationSelection)
        .await
        .map_err(|e| {
            tracing::error!(
                target: "tenancy.privatization",
                error = %e,
                "could not acquire the maintenance connection"
            );
            ApiError::InternalError {
                message: "Failed to acquire a maintenance connection".to_string(),
            }
        })
}

/// Load a plan on the ACTOR's own stamped connection, or 404.
///
/// Step 1 of the four-step skeleton this module's mid-file banner describes. The
/// 404 is 087's SELECT policy answering, not a handler decision, and it is a 404
/// rather than a 403 on purpose: distinguishing "no such plan" from "a plan you
/// may not read" is an existence oracle over every other admin's plans.
#[cfg(feature = "db")]
async fn load_plan_for_actor(
    state: &AppState,
    viewer: &epigraph_db::visibility::Viewer,
    plan_id: Uuid,
) -> Result<epigraph_db::repos::privatization::PlanRow, ApiError> {
    use epigraph_db::repos::privatization::PrivatizationRepository;

    let mut read = state.read_as(viewer).await.map_err(scoped_read_error)?;
    let plan = PrivatizationRepository::load_plan_conn(&mut read, plan_id).await?;
    // COMMITTED BEFORE THE CALLER ACQUIRES FROM THE MAINTENANCE POOL. Holding
    // this open across that acquire pins one connection from each of two pools
    // for the width of a request, and the maintenance pool is deliberately the
    // smallest in the process.
    read.commit().await.map_err(scoped_read_error)?;

    plan.ok_or_else(|| ApiError::NotFound {
        entity: "privatization plan".to_string(),
        id: plan_id.to_string(),
    })
}

/// `410 Gone` once a plan is older than the preview TTL.
///
/// §6.5.5's refusal thresholds: "Plan older than 4 h → `410 Gone`". The window
/// is on ACTING ON A PREVIEW — the corpus moves, and a four-hour-old selection
/// is a description of a graph that no longer exists. `revert` deliberately does
/// not call this; see its doc.
#[cfg(feature = "db")]
fn refuse_if_expired(plan: &epigraph_db::repos::privatization::PlanRow) -> Result<(), ApiError> {
    let expires_at = plan.created_at + chrono::Duration::hours(PLAN_TTL_HOURS);
    if chrono::Utc::now() > expires_at {
        return Err(ApiError::Gone {
            reason: format!(
                "this preview expired at {expires_at}; re-run the selection. A frozen plan \
                 describes the graph as it was, and the graph has had {PLAN_TTL_HOURS} hours to \
                 move"
            ),
        });
    }
    Ok(())
}

/// `409` unless the caller echoed the plan's CURRENT digest (acceptance clause 2).
///
/// # It is compared as bytes, after a strict parse
///
/// The wire form is `b3:` plus 64 lowercase hex characters, which is what
/// `create_plan` emits. A malformed token is the SAME 409 as a wrong one and not
/// a 400: both mean "you did not echo the digest of the plan you are applying",
/// and splitting them tells a caller whether their guess was well-formed.
///
/// The comparison is `==` on `[u8]` and not `constant_time_eq`. The digest is
/// not a secret — `create_plan` returns it and `GET /plans/:id` would too — it
/// is a STALENESS token, so there is nothing for a timing oracle to recover that
/// the caller was not already given.
///
/// # What the digest does NOT bind
///
/// `PrivatizationRepository::plan_digest` covers the selection SET and not
/// `target_group_id`, `mode`, `on_conflict` or `pad_to`. So this proves the
/// corpus has not moved under the plan; it does not prove the caller is applying
/// the plan they think they are. That is what `plan_id` in the path is for, and
/// the repo function's doc says so.
#[cfg(feature = "db")]
fn refuse_stale_digest(
    plan: &epigraph_db::repos::privatization::PlanRow,
    echoed: &str,
) -> Result<(), ApiError> {
    let stale = || ApiError::Conflict {
        reason: "the plan_digest you echoed is not this plan's current digest; the selection has \
                 moved underneath the plan. Re-run the preview and review it before applying"
            .to_string(),
    };
    let Some(stored) = plan.plan_digest.as_deref() else {
        return Err(stale());
    };
    let Some(hex_digits) = echoed.strip_prefix("b3:") else {
        return Err(stale());
    };
    let Ok(bytes) = hex::decode(hex_digits) else {
        return Err(stale());
    };
    if bytes != stored {
        return Err(stale());
    }
    Ok(())
}

/// Which job a dispatch enqueues.
#[cfg(feature = "db")]
#[derive(Clone, Copy)]
enum DispatchKind {
    /// `privatization_apply`.
    Apply,
    /// `privatization_revert`.
    Revert,
}

/// The `security_events.event_type` `GET /audit` writes.
///
/// §6.5.7's `/audit` row: "every read writes a `security_events` row". A distinct
/// type from [`DISPATCH_EVENT_TYPE`], because an audit READ and a privatization
/// DISPATCH are different events and a single type would make the timeline
/// unfilterable.
#[cfg(feature = "db")]
const AUDIT_READ_EVENT_TYPE: &str = "privatization_audit_read";

/// The `security_events.event_type` `apply`/`revert` write and the job handler's
/// sixth condition looks for.
#[cfg(feature = "db")]
const DISPATCH_EVENT_TYPE: &str = epigraph_jobs::privatization::DISPATCH_EVENT_TYPE;

/// A fresh correlation id: 32 hex characters, inside `varchar(64)`.
///
/// Hyphenless so the same token is a legal `security_events.correlation_id`, a
/// legal `privatization_audit.correlation_id` and a legal JSON string without
/// any per-surface reformatting that could make three tables disagree about
/// which request they describe.
#[cfg(feature = "db")]
fn new_correlation_id() -> String {
    Uuid::new_v4().simple().to_string()
}

/// The one transaction that turns an authorized request into a running plan.
///
/// The `security_events` row, the CONDITIONAL state flip, the audit row and the
/// `jobs` row, in that order, on one maintenance connection, committed together.
///
/// # Why all four and not three
///
/// FINAL-PLAN §6.5.5's sixth re-validation condition is that `dispatched_by`
/// matches the `agent_id` on the `security_events` row the HTTP layer wrote for
/// this `correlation_id`. `privatization_plans` has no `correlation_id` column —
/// migration 080 is applied and frozen — so the token rides in the job payload,
/// and the event and the flip must commit or roll back together or that
/// condition compares two facts from different worlds.
///
/// # The flip is conditional and a zero row count is a 409
///
/// `PlanTransition::Dispatch` carries `WHERE state = ANY($4)`. Two concurrent
/// `apply` calls therefore cannot both flip the plan and enqueue two jobs
/// against it; the loser is told the plan moved.
#[cfg(feature = "db")]
async fn dispatch(
    state: &AppState,
    plan: &epigraph_db::repos::privatization::PlanRow,
    actor: Uuid,
    to_state: &str,
    from_states: &[String],
    kind: DispatchKind,
) -> Result<(axum::http::StatusCode, Json<DispatchResponse>), ApiError> {
    use epigraph_db::repos::privatization::{
        PlanAuditEntry, PlanTransition, PrivatizationRepository,
    };
    use epigraph_db::repos::security_event::{SecurityEventRepository, SecurityEventRow};

    let correlation_id = new_correlation_id();
    let job = match kind {
        DispatchKind::Apply => epigraph_jobs::EpiGraphJob::PrivatizationApply {
            plan_id: plan.id,
            dispatched_by: actor,
            correlation_id: correlation_id.clone(),
        },
        DispatchKind::Revert => epigraph_jobs::EpiGraphJob::PrivatizationRevert {
            plan_id: plan.id,
            dispatched_by: actor,
            correlation_id: correlation_id.clone(),
        },
    };
    let job_type = job.job_type().to_string();
    let payload = serde_json::to_value(&job).map_err(|e| {
        tracing::error!(target: "tenancy.privatization", error = %e, "job payload");
        ApiError::InternalError {
            message: "Failed to encode the privatization job".to_string(),
        }
    })?;

    let (mut maint, _bypass) = maintenance(state).await?;
    let mut tx = sqlx::Connection::begin(&mut *maint)
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;

    SecurityEventRepository::log_conn(
        &mut tx,
        &SecurityEventRow {
            id: Uuid::new_v4(),
            event_type: DISPATCH_EVENT_TYPE.to_string(),
            agent_id: Some(actor),
            success: Some(true),
            // The plan id and the target state, and NOT the item ids or any
            // content. `security_events` is read by a principal-keyed policy,
            // not by a group-admin one, so its `details` must not carry the
            // entity ids `privatization_plan_items` exists to fence.
            details: serde_json::json!({
                "plan_id": plan.id,
                "target_group_id": plan.target_group_id,
                "to_state": to_state,
                "item_count": plan.item_count,
            }),
            ip_address: None,
            user_agent: None,
            correlation_id: Some(correlation_id.clone()),
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .map_err(plan_write_error)?;

    let moved = PrivatizationRepository::transition_plan_conn(
        &mut tx,
        plan.id,
        PlanTransition::Dispatch {
            dispatched_by: actor,
            to_state,
            from_states,
        },
    )
    .await
    .map_err(plan_write_error)?;
    if moved == 0 {
        return Err(ApiError::Conflict {
            reason: "the plan moved while it was being dispatched; re-read it and try again"
                .to_string(),
        });
    }

    PrivatizationRepository::record_plan_audit_conn(
        &mut tx,
        PlanAuditEntry {
            plan_id: plan.id,
            actor_agent_id: actor,
            action: "plan.dispatch",
            kind: None,
            entity_id: None,
            plan_digest: plan.plan_digest.as_deref(),
            correlation_id: Some(&correlation_id),
        },
    )
    .await
    .map_err(plan_write_error)?;

    let job_id = PrivatizationRepository::enqueue_job_conn(&mut tx, &job_type, &payload)
        .await
        .map_err(plan_write_error)?;

    tx.commit()
        .await
        .map_err(|source| plan_write_error(epigraph_db::DbError::QueryFailed { source }))?;

    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(DispatchResponse {
            plan_id: plan.id,
            job_id,
            state: to_state.to_string(),
            correlation_id,
        }),
    ))
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
///
/// `items_by_state` is `None` here and filled in by `get_plan` alone: the list
/// endpoint would otherwise run one aggregate per row, and a page of five
/// hundred plans is five hundred `GROUP BY`s to serve a field nobody asked for.
#[cfg(feature = "db")]
fn summarise(row: epigraph_db::repos::privatization::PlanRow) -> PlanSummary {
    PlanSummary {
        plan_id: row.id,
        state: row.state,
        mode: row.mode,
        target_group_id: row.target_group_id,
        item_count: row.item_count,
        authors_losing_count: row.authors_losing_count,
        approved_by: row.approved_by,
        approved_at: row.approved_at,
        dispatched_by: row.dispatched_by,
        cursor_depth: row.cursor_depth,
        drift_count: row.drift_count,
        items_by_state: None,
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

/// `POST /api/v1/admin/privatization/plans/:id/approve` without the `db`
/// feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn approve_plan(
    State(_state): State<AppState>,
    Path(_plan_id): Path<Uuid>,
) -> Result<Json<PlanStateResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `POST /api/v1/admin/privatization/plans/:id/apply` without the `db` feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn apply_plan(
    State(_state): State<AppState>,
    Path(_plan_id): Path<Uuid>,
    Json(_body): Json<ApplyRequest>,
) -> Result<Json<DispatchResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `POST /api/v1/admin/privatization/plans/:id/abort` without the `db` feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn abort_plan(
    State(_state): State<AppState>,
    Path(_plan_id): Path<Uuid>,
) -> Result<Json<PlanStateResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `POST /api/v1/admin/privatization/plans/:id/revert` without the `db` feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn revert_plan(
    State(_state): State<AppState>,
    Path(_plan_id): Path<Uuid>,
    Json(_body): Json<RevertRequest>,
) -> Result<Json<DispatchResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `GET /api/v1/admin/privatization/audit` without the `db` feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn get_audit(
    State(_state): State<AppState>,
    Query(_params): Query<AuditQueryParams>,
) -> Result<Json<AuditResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `GET /api/v1/admin/privatization/plans/:id/seal-manifest` without the `db`
/// feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn seal_manifest(
    State(_state): State<AppState>,
    Path(_plan_id): Path<Uuid>,
    Query(_params): Query<ManifestQuery>,
) -> Result<Json<SealManifest>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `POST /api/v1/admin/privatization/plans/:id/seal-commit` without the `db`
/// feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn seal_commit(
    State(_state): State<AppState>,
    Path(_plan_id): Path<Uuid>,
    Json(_body): Json<SealCommitRequest>,
) -> Result<Json<CommitResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `GET /api/v1/admin/privatization/plans/:id/unseal-manifest` without the `db`
/// feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn unseal_manifest(
    State(_state): State<AppState>,
    Path(_plan_id): Path<Uuid>,
    Query(_params): Query<ManifestQuery>,
) -> Result<Json<UnsealManifest>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}

/// `POST /api/v1/admin/privatization/plans/:id/unseal-commit` without the `db`
/// feature.
///
/// # Errors
///
/// Always `503`.
#[cfg(not(feature = "db"))]
pub async fn unseal_commit(
    State(_state): State<AppState>,
    Path(_plan_id): Path<Uuid>,
    Json(_body): Json<UnsealCommitRequest>,
) -> Result<Json<CommitResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Privatization requires database".to_string(),
    })
}
