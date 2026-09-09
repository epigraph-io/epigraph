//! D4 privatization: the selection pass, the boundary survey, and the
//! actor-scoped rendering pass.
//!
//! This is the first Rust caller of `epigraph_privatization_closure` and
//! `epigraph_content_lineage_hull` (migration 080). Everything in this module
//! is READ-ONLY: it computes what a privatization *would* select. Persisting a
//! plan, approving it, applying it and reverting it are not here — see
//! "What this module deliberately does not do" below.
//!
//! # Two passes, two authorities — and why they are two functions
//!
//! FINAL-PLAN §6.5.2 records a previous revision of this design that shipped a
//! cross-tenant read oracle. The fix is a split that has to be visible at the
//! signature, because both halves are single-argument changes away from being
//! wrong in opposite directions:
//!
//! * **Selection** ([`PrivatizationRepository::select_closure`],
//!   [`PrivatizationRepository::select_content_lineage_hull`],
//!   [`PrivatizationRepository::boundary_edge_counts`],
//!   [`PrivatizationRepository::authors_losing_own_claims`]) runs **unfiltered**,
//!   under a bypass viewer. It must be unfiltered: a selection narrowed to what
//!   the actor can see would silently omit exactly the rows privatization
//!   exists to catch, and report success.
//! * **Rendering** ([`PrivatizationRepository::visible_previews`],
//!   [`PrivatizationRepository::visible_boundary_edges`]) runs under the
//!   **actor's own** viewer. An entity the actor cannot read contributes to a
//!   COUNT and never contributes an id or a byte of content.
//!
//! Getting this backwards produces either a wrong plan (filtering selection) or
//! the oracle (filtering nothing). The asymmetry is the design:
//! **counts are not re-filtered; ids and content are.**
//!
//! ## How much of that split the compiler enforces, stated plainly
//!
//! Not much, and the honest accounting matters more than the claim. The two
//! rendering functions REFUSE a bypass viewer at runtime, so that direction —
//! the one whose fail-open is a disclosure — holds in a release build. The six
//! selection functions carry `debug_assert!` only, which is compiled out under
//! the default release profile; their fail-open is an under-selected plan,
//! which is wrong but visible. What no guard here provides is a TYPE-level
//! distinction between the two passes' outputs: [`SelectedClaim`] and
//! [`ItemPreview`] carry a `Uuid` apiece and the compiler cannot tell a caller
//! which one it is holding. **Closing that is an obligation on whichever slice
//! first gives this module a caller that reaches the wire** — a newtype whose
//! only exit takes the actor's viewer, or a composed entry point that performs
//! both passes itself. It is deliberately not discharged by a module that has
//! no caller at all, and it is deliberately not left unsaid.
//!
//! ## The marker in a selection statement is not decoration
//!
//! Each selection statement carries a `/* {VISIBILITY:… } */` marker even
//! though it is always called with a bypass viewer, for which
//! `Viewer::render_fragment` renders the empty string and binds nothing. Two
//! reasons, neither stylistic:
//!
//! 1. It is the honest spelling. `visibility_lint.rs` requires a viewer-taking
//!    repo function to spend its viewer, and the alternative —
//!    a `-- VISIBILITY-EXEMPT:` annotation — would be a *new* entry in
//!    `EXPECTED_EXEMPTIONS`, whose own failure message says "a new exemption on
//!    a READ path is almost certainly a leak being annotated rather than
//!    fixed". Splicing a bypass viewer is not an exemption and does not need
//!    one.
//! 2. It makes a mis-call fail CLOSED. If a future caller hands one of these a
//!    `Scoped` viewer, the predicate materialises and the selection
//!    *under*-selects — a visibly wrong plan — rather than quietly returning
//!    the whole corpus. [`PrivatizationRepository::select_closure`] additionally
//!    `debug_assert!`s the bypass shape so the mistake is loud in tests.
//!
//! ## Which connection calls the selection functions, and what is re-filtered
//!
//! Migration 080's header leaves two questions to the first caller by name.
//! Answered here rather than left to be inferred:
//!
//! 1. **Which connection.** The MAINTENANCE one. This is forced, not chosen:
//!    `Viewer::system` cannot be built without a `MaintenanceLease`, which only
//!    `ScopedPool::unscoped_for_maintenance` mints, and `EXECUTE` on both
//!    selection functions is granted to `epigraph_maintenance` alone (checked
//!    from `pg_proc.proacl`, not from the migration text). An app connection
//!    can neither mint the viewer nor call the functions.
//! 2. **Whether returned ids are re-filtered against the requester's viewer.**
//!    ASYMMETRICALLY, and that asymmetry is the whole design. **Counts are
//!    not** — re-filtering them would report a plan smaller than the one that
//!    will actually be applied, which is a wrong plan. **Ids and content are** —
//!    they only ever leave this module through [`Self::visible_previews`] and
//!    [`Self::visible_boundary_edges`], both of which take the actor's viewer.
//!
//! Note what the invoker bound does NOT buy here. Both functions are
//! `SECURITY INVOKER`, but `epigraph_bypass()` is true for
//! `epigraph_maintenance`, so on the only connection that can call them the
//! invoker bound admits every row. The unfiltered result is a property of the
//! caller's authority, not something the function restrains — which is why the
//! rendering split above is the control and the invoker mode is not.
//!
//! # Caps REFUSE; they do not truncate
//!
//! Migration 080's header defers two silent truncations to this layer by name,
//! and FINAL-PLAN §3.1 requires that exceeding a cap be "a 400, not a
//! truncation":
//!
//! * `epigraph_privatization_closure`'s `LIMIT p_node_cap` has no `ORDER BY`,
//!   so a truncated result is also a nondeterministic one. This module asks the
//!   function for `node_cap + 1` rows and refuses with
//!   [`SelectionRefusal::NodeCapExceeded`] when it gets them, so the cap is
//!   detected rather than absorbed.
//! * `epigraph_content_lineage_hull`'s `array_length(path,1) < 64` walk cap
//!   truncates a long `supersedes` chain with no signal. This module does not
//!   rely on that bound at all — see the next section.
//!
//! # The hull is iterated to a fixed point, which closes two inherited holes
//!
//! [`PrivatizationRepository::select_content_lineage_hull`] does not call the
//! SQL hull once and keep the answer. It re-seeds the function with everything
//! found so far and repeats until a round adds nothing. Two consequences, both
//! of which discharge obligations migration 080 assigned to this caller
//! explicitly:
//!
//! * The SQL hull expands `step_lineage_id` siblings in a **single
//!   non-recursive CTE** that is never fed back into its recursive `chain`
//!   term, so a sibling's own predecessors, successors and cousins are not
//!   walked. Re-seeding makes the sibling arm transitive at the repo layer
//!   without altering applied DDL.
//! * A `supersedes` chain longer than the SQL walk's 64-hop bound is completed
//!   across rounds instead of being cut, because each round starts from the
//!   frontier the previous one reached.
//!
//! Termination is monotone: the accumulated set only grows, is bounded by
//! `node_cap`, and the loop exits the first time a round contributes no new id.
//!
//! Rounds run in ascending depth bands so that
//! `privatization_plan_items.depth`'s documented rule — "hull members inherit
//! their anchor's depth" — resolves to the LOWEST anchor depth when a hull
//! member attaches to two anchors at different depths. That matches the
//! closure's own `MIN(lvl)` aggregate rather than inventing a second tiebreak.
//!
//! # The boundary survey is a `claim`-to-`claim` survey
//!
//! [`PrivatizationRepository::boundary_edge_counts`],
//! [`PrivatizationRepository::omitted_edge_types`] and
//! [`PrivatizationRepository::visible_boundary_edges`] all restrict to
//! `source_type = 'claim' AND target_type = 'claim'`. `edges` endpoints are
//! polymorphic, so an edge from a selected claim's evidence to an entity
//! outside the selection is a genuine straddling boundary that these three do
//! not report. That is a known INCOMPLETENESS of the numbers, recorded here so
//! a later slice does not serialise a subtotal into a field named `total`: the
//! honest field name for what this module computes is
//! `boundary_edges.claim_to_claim`.
//!
//! # Persistence, and what it is still not
//!
//! Migration **087** gives both plan tables their SELECT and INSERT policies, so
//! from this slice on the module DOES persist. [`UnfilteredSelection::freeze_into`]
//! materialises the frozen item set on the maintenance connection (087's INSERT
//! arm is `epigraph_bypass()` only), and
//! [`PrivatizationRepository::load_plan_conn`],
//! [`PrivatizationRepository::list_plans_conn`] and
//! [`PrivatizationRepository::load_plan_items_conn`] read it back through 087's
//! SELECT policies — which is why those three take a connection and **no**
//! `Viewer`: neither table has a `visibility` column, their tenancy IS the
//! policy, and a `Viewer` parameter they could not spend would be the annotated
//! fail-open `visibility_lint.rs::EXPECTED_EXEMPTIONS` exists to refuse. **They
//! must be given a STAMPED app connection.** On the maintenance connection
//! `epigraph_bypass()` is true, the policy admits every row, and the read
//! becomes the cross-tenant oracle §6.5.2 documents.
//!
//! Migration **088** adds the UPDATE policies — bypass-only on both `USING` and
//! `WITH CHECK` — and the two matching rows are deleted from
//! `rls_enforcement.rs::DELIBERATELY_UNCOVERED` in the same commit, because that
//! register is exact in both directions. DELETE stays uncovered on both tables
//! and stays registered: a plan is the record that a privatization was attempted
//! and is never deleted.
//!
//! So this module DOES now mutate `claims.visibility` and
//! `claims.owner_group_id` — see "Apply / revert" below. Everything above the
//! `APPLY / REVERT` banner is still read-only; everything below it runs on the
//! MAINTENANCE connection, is unreachable from the app role, and is NOT where
//! the authorization lives. FINAL-PLAN §6.5.5's re-validation in
//! `epigraph-jobs/src/privatization.rs` is.
//!
//! # The two passes are now distinguishable BY TYPE
//!
//! The module doc above used to end by owing a type-level split to "whichever
//! slice first gives this module a caller that reaches the wire". This is that
//! slice, and [`UnfilteredSelection`] is the discharge. It wraps the selection
//! pass's `Vec<SelectedClaim>` in a struct with a PRIVATE field, and every exit
//! that carries an entity id is one of exactly two shapes:
//!
//! * it takes the **actor's** `Viewer` ([`UnfilteredSelection::render_previews`],
//!   [`UnfilteredSelection::render_boundary_edges`],
//!   [`UnfilteredSelection::visible_count`]), or
//! * it writes into a FORCE-protected table and returns no id
//!   ([`UnfilteredSelection::freeze_into`]).
//!
//! Everything else it exposes is a COUNT. There is no `ids()` accessor and no
//! `Deref`, so a handler cannot obtain a bare `Uuid` from the selection pass at
//! all — which is the property the old `SelectedClaim`/`ItemPreview` pair could
//! not express, both being a `Uuid` the compiler could not tell apart.
//!
//! The remaining exits are [`UnfilteredSelection::into_selected`] and
//! [`UnfilteredSelection::from_selected`], and they exist because four
//! integration-test binaries in another crate exercise this module directly, so
//! Rust visibility cannot hold the line. The request path is held off them by a
//! SOURCE lint instead:
//! `crates/epigraph-db/tests/locked_decisions.rs::d4_the_request_path_reaches_privatization_only_through_the_composed_entry_point`
//! bans them, and the selection-pass entry points, from
//! `epigraph-api/src/routes/` and `epigraph-mcp/src/tools/` outright.

use sqlx::PgConnection;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

/// Edge relationships that point at CONTAINERS rather than at restated content.
///
/// Migration 080's deferral list names these four and requires the caller to
/// refuse them: traversing `within_frame` from a claim reaches the frame, and
/// from the frame every other claim in it — which is a privatization of
/// everything that shares a container, not of the content the operator named.
/// Passing them to the SQL function is not an error there; this layer is the
/// gate.
pub const STRUCTURAL_EDGE_TYPES: &[&str] =
    &["within_frame", "scoped_by", "member_of", "perspective_of"];

/// Relationships that restate or decompose content, and so default to ON.
///
/// Privatizing a claim while leaving its decomposition public leaves the
/// content readable through the atoms.
pub const RESTATEMENT_EDGE_TYPES: &[&str] = &["decomposes_to", "derived_from"];

/// Which tier an edge relationship falls into (migration 080, deferral 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeTypeTier {
    /// Restates or decomposes content. Defaults on.
    Restatement,
    /// Asserts something ABOUT a claim without restating it (`supports`,
    /// `contradicts`, …). Defaults off: privatizing every claim that disagrees
    /// with a private one is not what the operator asked for.
    Epistemic,
    /// Points at a container. Always refused.
    Structural,
}

/// Classify a relationship, case-insensitively.
///
/// Case folding is mandatory rather than cosmetic: migration 011 documents
/// tens of thousands of rows carrying `DERIVED_FROM` alongside `derived_from`,
/// and a tier check that matched one spelling would let the other through.
#[must_use]
pub fn classify_edge_type(relationship: &str) -> EdgeTypeTier {
    let lowered = relationship.to_ascii_lowercase();
    if STRUCTURAL_EDGE_TYPES.contains(&lowered.as_str()) {
        EdgeTypeTier::Structural
    } else if RESTATEMENT_EDGE_TYPES.contains(&lowered.as_str()) {
        EdgeTypeTier::Restatement
    } else {
        EdgeTypeTier::Epistemic
    }
}

/// Direction of closure traversal, as `epigraph_privatization_closure` spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosureDirection {
    /// Follow `source_id -> target_id` only.
    Out,
    /// Follow `target_id -> source_id` only.
    In,
    /// Both.
    Both,
}

impl ClosureDirection {
    /// The literal the SQL function compares `p_direction` against.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ClosureDirection::Out => "out",
            ClosureDirection::In => "in",
            ClosureDirection::Both => "both",
        }
    }
}

/// A refusal the route layer turns into a 400.
///
/// These are CLIENT errors — the request names a traversal this system will not
/// perform, or one whose honest answer does not fit inside the caller's own
/// caps. They are deliberately not [`DbError`] variants: a truncated selection
/// is not a database fault, and collapsing it into `QueryFailed` would surface
/// as a 500 and lose the reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectionRefusal {
    /// A structural edge type was requested. See [`STRUCTURAL_EDGE_TYPES`].
    #[error(
        "edge type '{relationship}' is structural and points at a container; \
         privatizing through it would select every entity sharing that container"
    )]
    StructuralEdgeType { relationship: String },

    /// The closure emitted more rows than `node_cap` allows.
    ///
    /// Reported rather than truncated: the SQL function's `LIMIT` carries no
    /// `ORDER BY`, so the rows that survive truncation are not merely a subset,
    /// they are an ARBITRARY subset that can differ between two runs of the
    /// same request.
    ///
    /// The comparison is against the function's own output cardinality, which
    /// includes ids that resolve to no live claim row. That is deliberate and
    /// fail-closed: an unresolved id still consumed a `LIMIT` slot, so it may
    /// have displaced a real one, and a caller cannot be told a selection is
    /// complete when we cannot show that it is.
    #[error(
        "selection exceeds node_cap {node_cap}; narrow the seeds, lower max_depth, \
         or raise the cap — a truncated selection is not a smaller privatization, \
         it is an incomplete one"
    )]
    NodeCapExceeded { node_cap: i32 },

    /// `node_cap` exceeds [`MAX_NODE_CAP`].
    ///
    /// Distinct from [`Self::NodeCapExceeded`], which is about a SELECTION that
    /// overflows the caller's own cap. This one is about the REQUEST asking for
    /// a cap larger than the system will honour, and FINAL-PLAN §3.1 requires it
    /// to be "a 400, not a truncation".
    #[error(
        "node_cap {requested} exceeds the system maximum of {maximum}; the ceiling is refused \
         rather than clamped, because a silently lowered cap produces a plan the operator did \
         not ask for and cannot tell apart from one that fits"
    )]
    NodeCapAboveSystemMaximum { requested: i32, maximum: i32 },

    /// `max_depth` exceeds [`MAX_TRAVERSAL_DEPTH`].
    #[error(
        "max_depth {requested} exceeds the system maximum of {maximum}; the ceiling is refused \
         rather than clamped, for the reason node_cap's is"
    )]
    DepthAboveSystemMaximum { requested: i32, maximum: i32 },

    /// No seeds were supplied.
    #[error("a privatization selection needs at least one seed")]
    NoSeeds,

    /// `max_depth` or `node_cap` was non-positive.
    #[error("{parameter} must be positive, got {value}")]
    NonPositiveBound { parameter: &'static str, value: i32 },

    /// A rendering-pass function was handed a bypass viewer.
    ///
    /// This is the one contract in this module that is checked at RUNTIME
    /// rather than by `debug_assert!`, because it is the only one whose
    /// fail-open direction is a disclosure rather than a wrong answer, and
    /// `debug_assertions` is off in a release profile.
    #[error(
        "the rendering pass carries the ACTOR's own authority and refuses a bypass viewer; \
         ids and content are the half of a preview that must be filtered"
    )]
    BypassViewerInRenderingPass,
}

/// Either a client-side refusal or a genuine database fault.
#[derive(Debug, thiserror::Error)]
pub enum SelectionError {
    /// The request is not one this system will answer. Maps to 400.
    #[error(transparent)]
    Refused(#[from] SelectionRefusal),
    /// The database failed. Maps to 500.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// One entity the selection would privatize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedClaim {
    /// The claim's id.
    pub claim_id: Uuid,
    /// Hops from the nearest seed. `0` = seed.
    pub depth: i32,
    /// Provenance: `seed`, `closure:<relationship>`, `hull:supersedes` or
    /// `hull:step_lineage`.
    pub via: String,
}

/// FINAL-PLAN §3.1's hard ceiling on `node_cap`.
///
/// A request naming a larger cap is refused with
/// [`SelectionRefusal::NodeCapAboveSystemMaximum`] — "a 400, not a truncation",
/// in the plan's own words. Enforced HERE rather than in the route so that every
/// caller of [`PrivatizationRepository::select_closure`] gets it, including the
/// MCP tools a later slice adds.
pub const MAX_NODE_CAP: i32 = 250_000;

/// FINAL-PLAN §3.1's hard ceiling on `max_depth`.
///
/// See [`MAX_NODE_CAP`] for why it lives at this layer.
pub const MAX_TRAVERSAL_DEPTH: i32 = 6;

/// The request shape for a closure traversal.
///
/// `max_depth` and `node_cap` are the CALLER's bounds. They are checked for
/// positivity AND against the two system ceilings [`MAX_NODE_CAP`] and
/// [`MAX_TRAVERSAL_DEPTH`]. Those ceilings answer a different question from
/// [`SelectionRefusal::NodeCapExceeded`], which is about the SELECTION exceeding
/// the cap the caller asked for; these are about the request asking for more
/// than the system will honour at all.
#[derive(Debug, Clone, Copy)]
pub struct ClosureRequest<'a> {
    /// Claim ids the operator named.
    pub seeds: &'a [Uuid],
    /// Relationships to traverse. Each is tier-checked before any SQL runs.
    pub edge_types: &'a [String],
    /// Traversal direction.
    pub direction: ClosureDirection,
    /// Maximum hops from a seed.
    pub max_depth: i32,
    /// Maximum total nodes. Exceeding it is a refusal, not a truncation.
    pub node_cap: i32,
}

/// A boundary edge: one endpoint inside the selection, one outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryEdgeCount {
    /// The relationship, lowercased.
    pub relationship: String,
    /// How many boundary edges carry it.
    pub count: i64,
}

/// An edge type that was NOT traversed but would have extended the selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmittedEdgeTypeWarning {
    /// The relationship, lowercased.
    pub relationship: String,
    /// How many additional claims one more hop along it would have added.
    pub would_add: i64,
}

/// A rendered item the actor is allowed to see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemPreview {
    /// The claim id. Present ONLY because the actor can read this claim.
    pub claim_id: Uuid,
    /// A short prefix of `content`.
    pub preview: String,
}

/// How many characters of `content` a preview carries.
pub const PREVIEW_CHARS: i32 = 120;

/// How many candidate ids [`UnfilteredSelection::render_previews`] draws before
/// it renders anything.
///
/// The sample the operator sees is at most twenty-five items, but the actor may
/// be unable to read most of a stratified draw, so the window is larger than the
/// sample. It is not unbounded: a selection may hold [`MAX_NODE_CAP`] items and
/// each rendered row carries [`PREVIEW_CHARS`] of content.
pub const SAMPLE_CANDIDATE_WINDOW: usize = 500;

/// The largest boundary-edge SAMPLE
/// [`PrivatizationRepository::visible_boundary_edges`] will return.
///
/// A sample exists so the operator can inspect a few straddling edges; the
/// decision-relevant number is the count. Without a ceiling a caller could ask
/// for the whole boundary and turn the sample into the survey.
pub const MAX_BOUNDARY_EDGE_SAMPLE: i64 = 1000;

/// A persisted plan row, as migration 087's SELECT policy admits it.
///
/// `expires_at` is deliberately ABSENT: FINAL-PLAN §6.5.2 gives a preview a 4 h
/// TTL, migration 080 has no column for it, and 080 is applied and frozen. The
/// value is therefore derived by the serialising layer from `created_at`, and
/// naming it here as if it were stored would be the drift this series refuses.
///
/// # The apply-time columns are here, and they are the LIVE PROGRESS half
///
/// `approved_by`, `approved_at`, `dispatched_by`, `cursor_depth` and
/// `drift_ids` were absent while nothing could write them. They are added by the
/// slice that makes them move, which is what `F-PR18b-preview-schema-is-a-subset`
/// assigns here: §6.5.7 gives `GET /plans/:id` "preview + live progress", and
/// live progress IS the cursor and the per-item state.
///
/// `drift_ids` is exposed as a COUNT and not as the array. The ids are claim
/// ids that a reader of this row may not be entitled to read — administering a
/// plan's target group is not the same property as being able to read every
/// claim the drift rescan found — and this struct crosses no viewer.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PlanRow {
    /// The plan's id.
    pub id: Uuid,
    /// `draft`|`selecting`|`previewed`|… See 080's `pp_state_check`.
    pub state: String,
    /// `restrict` or `seal`.
    pub mode: String,
    /// The group the plan would move its items into.
    pub target_group_id: Uuid,
    /// BLAKE3 over the sorted `(kind, entity_id)` pairs; an apply must echo it.
    pub plan_digest: Option<Vec<u8>>,
    /// How many entities the frozen set holds.
    pub item_count: i32,
    /// How many distinct authors would lose access to their own claims.
    pub authors_losing_count: i32,
    /// Whether the author-loss acknowledgement has been given.
    pub acknowledge_author_loss: bool,
    /// `abort`|`skip`|`reassign`.
    pub on_conflict: String,
    /// Seal-mode plaintext padding bucket.
    pub pad_to: i32,
    /// The agent that created the plan.
    pub created_by: Uuid,
    /// The second instance admin that approved it, if any.
    pub approved_by: Option<Uuid>,
    /// When the approval was given.
    pub approved_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The agent whose `apply` flipped the plan to `applying`.
    pub dispatched_by: Option<Uuid>,
    /// The depth band the last committed batch reached. Apply walks deepest
    /// first, so this DESCENDS as the job progresses.
    pub cursor_depth: Option<i32>,
    /// How many restatement-tier drifts the post-apply rescan found. A COUNT;
    /// see the type's doc for why the ids do not travel on this struct.
    pub drift_count: i64,
    /// When the plan was created. The TTL is measured from here.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// The columns of `privatization_plans` the projection above serves, spelled
/// once so `load_plan_conn`, `list_plans_conn` and the `FOR UPDATE` re-read
/// cannot drift apart.
///
/// `drift_ids` is projected as `cardinality(...)`, which is what makes the array
/// itself unable to leave the database through this struct.
const PLAN_ROW_COLUMNS: &str = "p.id, p.state, p.mode, p.target_group_id, p.plan_digest, \
     p.item_count, p.authors_losing_count, p.acknowledge_author_loss, \
     p.on_conflict, p.pad_to, p.created_by, p.approved_by, p.approved_at, \
     p.dispatched_by, p.cursor_depth, \
     cardinality(p.drift_ids)::bigint AS drift_count, p.created_at";

/// One row of a plan's frozen item set.
///
/// `entity_id` is present here because the row came off a connection 087's
/// policy already narrowed to a plan the caller administers. It is NOT yet
/// safe to serialise: administering the target group does not imply being able
/// to read every selected claim. See
/// [`PrivatizationRepository::load_plan_items_conn`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PlanItemRow {
    /// `claim` or `evidence`.
    pub kind: String,
    /// The selected entity.
    pub entity_id: Uuid,
    /// Hops from the nearest seed.
    pub depth: i32,
    /// Provenance, as [`SelectedClaim::via`] spells it.
    pub via: Option<String>,
    /// `pending`|`applied`|`skipped`|`failed`|`reverted`.
    pub state: String,
}

/// One locked row of a plan's remaining work, as the apply/revert batch sees it.
///
/// Distinct from [`PlanItemRow`], which is the READ-surface projection and
/// carries `via` and `state` for rendering. This one carries the `before_*`
/// tenancy the revert restores and omits everything the batch does not need, so
/// a batch of 50 does not materialise 50 rendering strings.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PlanWorkItem {
    /// `claim` or `evidence`. Every item this build produces is a `claim`.
    pub kind: String,
    /// The selected entity.
    pub entity_id: Uuid,
    /// Hops from the nearest seed. The batch order's primary key.
    pub depth: i32,
    /// The visibility captured at freeze time; what a revert restores.
    pub before_visibility: String,
    /// The owning group captured at freeze time.
    pub before_owner_group_id: Uuid,
}

/// A state transition [`PrivatizationRepository::transition_plan_conn`] performs.
///
/// An enum rather than four functions, so the guard conditions that make each
/// transition safe live in ONE statement each and next to each other. See that
/// function's doc for what is checked here and what is checked by 080's
/// `pp_four_eyes` CHECK and 081's approver guard.
#[derive(Debug, Clone, Copy)]
pub enum PlanTransition<'a> {
    /// The second instance admin approves. Refused unless the plan is
    /// `previewed` and carries no approver yet.
    Approve {
        /// The approving agent. Never `created_by` — `pp_four_eyes` is what
        /// makes that true rather than this type.
        approver: Uuid,
    },
    /// The HTTP layer flips the plan into a running state and hands it to the
    /// queue. The cursor is cleared, because a re-dispatch restarts the walk
    /// from the item states rather than from a stale position.
    Dispatch {
        /// The agent whose `apply` or `revert` this is.
        dispatched_by: Uuid,
        /// `applying` or `reverting`.
        to_state: &'a str,
        /// The states this transition is legal from. A plan in any other state
        /// is untouched and the caller sees a zero row count.
        from_states: &'a [String],
    },
    /// The handler records the last committed batch's position.
    Cursor {
        /// `claim` or `evidence`.
        kind: &'a str,
        /// The depth band the batch ended in.
        depth: i32,
        /// The last entity in the batch's total order.
        id: Uuid,
    },
    /// The handler records the post-apply rescan's answer, and NOTHING else.
    ///
    /// Separate from [`Self::Finish`] on purpose. The rescan runs while the plan
    /// is still `applying`, and an arm that wrote `state` as well would have to
    /// name the state the plan is already in — which is an unconditional write
    /// of `applying` that would resurrect a plan an operator aborted a moment
    /// earlier.
    Drift {
        /// The restatement-tier ids the rescan found.
        ids: &'a [Uuid],
    },
    /// The handler records a terminal state.
    ///
    /// CONDITIONAL on the state it expects to find, for the same reason
    /// [`Self::Dispatch`] is: `POST …/abort` can commit between the last batch
    /// and this write, and a terminal state written over `failed` undoes the
    /// operator's decision one statement later.
    Finish {
        /// `applied`|`applied_with_drift`|`failed`|`reverted`.
        state: &'a str,
        /// The states this transition is legal from. An empty slice means
        /// unconditional, which is what `abort` itself uses.
        from_states: &'a [String],
    },
}

/// One PLAN-level `privatization_audit` row.
///
/// The item-level rows are written set-based by
/// [`PrivatizationRepository::record_item_audit_conn`], which reads the
/// before/after tenancy out of the database rather than taking it as an
/// argument; this shape is for the events that describe the PLAN — creation,
/// approval, dispatch, abort, drift — where there is no entity tenancy to
/// record.
#[derive(Debug, Clone, Copy)]
pub struct PlanAuditEntry<'a> {
    /// The plan this row describes.
    pub plan_id: Uuid,
    /// The agent the action is attributed to.
    pub actor_agent_id: Uuid,
    /// `plan.create`|`plan.approve`|`plan.dispatch`|`plan.abort`|`plan.drift`.
    pub action: &'a str,
    /// `claim` or `evidence` when the row is about one entity.
    pub kind: Option<&'a str>,
    /// The entity, for `plan.drift`.
    pub entity_id: Option<Uuid>,
    /// The digest the action was taken against.
    pub plan_digest: Option<&'a [u8]>,
    /// Matches `security_events.correlation_id` for the same request.
    pub correlation_id: Option<&'a str>,
}

/// Which way a per-item audit row is read off the two tables.
///
/// `privatization_plan_items.before_visibility` is written ONCE, by
/// [`UnfilteredSelection::freeze_into`], and nothing mutates it — it is the
/// pre-APPLY image for the whole life of the plan. So the same projection cannot
/// serve both directions: on revert it is the value the restore is writing, not
/// the value the row is coming from, and a row that recorded it in the `before`
/// column would say `public -> public` about an operation that went
/// `group -> public`. That is a wrong value on a shipped read surface —
/// `GET /admin/privatization/audit` serves both columns verbatim — and the audit
/// trail is what D4 leans on for after-the-fact accountability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemAuditDirection {
    /// Written AFTER the tenancy write. `before` is the frozen pre-apply pair,
    /// `after` is the row as it now stands.
    Apply,
    /// Written BEFORE the tenancy write. `before` is the row as it stands — the
    /// tenancy the apply gave it — and `after` is the frozen pre-apply pair the
    /// restore is about to write back.
    ///
    /// It carries the same stamp predicate as
    /// [`PrivatizationRepository::restore_claims_conn`], so the set of rows
    /// audited and the set of rows moved are the same set by construction rather
    /// than by the two statements happening to agree.
    Revert,
}

/// One batch of per-item audit rows.
///
/// A struct rather than eight positional parameters, on the
/// [`PlanAuditEntry`] precedent: `plan_id`, `actor_agent_id` and
/// `target_group_id` are all `Uuid` and all three have been transposed at least
/// once in review.
#[derive(Debug, Clone, Copy)]
pub struct ItemAuditBatch<'a> {
    /// The plan whose items these are.
    pub plan_id: Uuid,
    /// The agent the batch is attributed to.
    pub actor_agent_id: Uuid,
    /// `item.apply` or `item.revert`.
    pub action: &'a str,
    /// The entities in this batch.
    pub entity_ids: &'a [Uuid],
    /// Matches `security_events.correlation_id` for the dispatching request.
    pub correlation_id: Option<&'a str>,
    /// Which projection, and therefore which side of the tenancy write.
    pub direction: ItemAuditDirection,
    /// The plan's target group. Used by [`ItemAuditDirection::Revert`]'s stamp
    /// predicate; ignored on apply.
    pub target_group_id: Uuid,
}

/// Filters for `GET /admin/privatization/audit`.
///
/// There is deliberately no `actor_agent_id` filter and no free-text search: the
/// scoping that matters is migration 083's policy, and a filter the policy does
/// not narrow invites a caller to believe the absence of rows is an answer about
/// the corpus rather than about their own authority.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditQuery {
    /// Restrict to one plan.
    pub plan_id: Option<Uuid>,
    /// Restrict to one entity.
    pub entity_id: Option<Uuid>,
    /// Only rows at or after this instant.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// Page size. The caller clamps.
    pub limit: i64,
}

/// One `privatization_audit` row, as 083's policy admits it.
///
/// `before_owner_group_id` / `after_owner_group_id` are NOT projected. They are
/// group ids rather than claim ids, so they are a smaller disclosure than
/// `entity_id`, but they are also not part of any acceptance clause and this
/// surface is the one §6.5.8 calls the most sensitive read in the system.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    /// The audit row's own id.
    pub id: i64,
    /// The plan.
    pub plan_id: Uuid,
    /// Who did it.
    pub actor_agent_id: Uuid,
    /// What they did.
    pub action: String,
    /// `claim`|`evidence`, when the row is about one entity.
    pub kind: Option<String>,
    /// The entity. Present only where 083's policy admitted the entity arm.
    pub entity_id: Option<Uuid>,
    /// Tenancy before the action.
    pub before_visibility: Option<String>,
    /// Tenancy after the action.
    pub after_visibility: Option<String>,
    /// Matches the `security_events` row for the same request.
    pub correlation_id: Option<String>,
    /// When.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Everything [`PrivatizationRepository::create_previewed_plan`] writes.
///
/// A struct rather than nine positional arguments because two of the three
/// `Uuid`s and two of the three `i32`s are transposable at a call site without
/// a type error.
#[derive(Debug, Clone, Copy)]
pub struct NewPlan<'a> {
    /// `restrict` or `seal`.
    pub mode: &'a str,
    /// The group the plan would move its items into.
    pub target_group_id: Uuid,
    /// The request body, stored verbatim so a re-preview is reproducible.
    pub selector: &'a serde_json::Value,
    /// `abort`|`skip`|`reassign`.
    pub on_conflict: &'a str,
    /// Seal-mode plaintext padding bucket.
    pub pad_to: i32,
    /// The authenticated instance admin.
    pub created_by: Uuid,
    /// BLAKE3 over the frozen set.
    pub plan_digest: &'a [u8],
    /// The frozen set's cardinality.
    pub item_count: i32,
    /// [`PrivatizationRepository::authors_losing_own_claims`]'s answer.
    pub authors_losing_count: i32,
}

// =========================================================================
// SEAL — the §6.5.4 trusted computing base, as data.
// =========================================================================

/// The sentinel `claims.content` carries once a claim is sealed.
///
/// # The id is written WITHOUT hyphens and behind an `x`, and both are measured
///
/// FINAL-PLAN §6.5.4 specifies `'[sealed:' || claims.id::text || ']'` and
/// requires `array_length(tsvector_to_array(content_tsv), 1) <= 2`. **Those two
/// requirements are incompatible as written.** Measured on this database over
/// 3,000 random uuids, the plan's literal spelling yields between FIVE and TEN
/// lexemes, because the default parser splits a hyphenated token into its parts
/// and keeps the whole as well — and the count VARIES WITH THE UUID, which is
/// the opposite of the constant lexical footprint the clause is asking for.
///
/// Stripping the hyphens gets it to two or three. Three, not two, whenever the
/// hex happens to start in a way the parser reads as a numeric prefix followed
/// by a word. Prefixing the hex with a literal `x` makes the whole thing one
/// unambiguous word token: measured **exactly 2 lexemes across 60,000 random
/// uuids**, and `length(content)` exactly 42 for every one of them.
///
/// So the sentinel is `[sealed:x<32 hex chars>]`. The `x` is not decoration; it
/// is what makes the token count a constant rather than a function of the id.
///
/// The suffix itself is not cosmetic. It is what makes the sentinel distinct
/// per claim, so `content_tsv`, `length(content)` and any hash taken over
/// `content` differ between two sealed claims whose plaintexts were identical.
///
/// Written as a SQL fragment rather than formatted in Rust because the seal
/// UPDATE is set-based over a batch: the sentinel has to be computed per row by
/// the statement, not supplied per row by the caller.
const SEAL_CONTENT_SENTINEL: &str = "'[sealed:x' || replace(c.id::text, '-', '') || ']'";

/// [`SEAL_CONTENT_SENTINEL`] for `claim_versions`, which is keyed on its
/// parent claim so every version of one claim carries one sentinel.
const SEAL_VERSION_SENTINEL: &str = "'[sealed:x' || replace(v.claim_id::text, '-', '') || ']'";

/// The sentinel `evidence.raw_content` carries once its claim is sealed.
///
/// Not id-suffixed, and it does not need to be: `evidence` has no generated
/// tsvector, no uniqueness constraint over its content and no content hash, so
/// the three reasons the claim sentinel carries an id do not apply. One fixed
/// token is the smaller side channel.
const SEAL_EVIDENCE_SENTINEL: &str = "[sealed]";

/// `privacy_tier` on every encryption row.
///
/// `claim_encryption_privacy_tier_check` and
/// `evidence_encryption_privacy_tier_check` both pin the column to this single
/// value, so it is a constant rather than a parameter. **FINAL-PLAN §3's DDL
/// for `evidence_encryption` omits the column entirely**; the applied table has
/// it `NOT NULL`, and an INSERT written from the plan would fail at runtime.
const SEALED_PRIVACY_TIER: &str = "fully_private";

/// Derived tables whose rows are DELETED rather than encrypted on seal.
///
/// §6.5.4's argument for deleting rather than encrypting: these are *derived*,
/// re-derivable from the plaintext on unseal, and encrypting each would
/// multiply the key ceremony by a table shape apiece for no confidentiality
/// gain.
///
/// **`experiment_entity_mentions` is not in the plan's list and is in this
/// one.** It is the eighteenth claim-derived table in
/// `epigraph_propagate_tenancy`'s own `derived[]` array and it carries
/// `surface_form text NOT NULL` — the same column, on the same kind of row, as
/// `entity_mentions.surface_form`, which the plan does name. A seal that
/// emptied one and not the other would leave the extraction it exists to
/// destroy sitting one table over.
pub const SEAL_DELETE_TABLES: &[&str] = &[
    "triples",
    "entity_mentions",
    "experiment_entity_mentions",
    "reasoning_traces",
    "challenges",
    "experiment_triples",
];

/// One claim's plaintext trusted computing base, as the seal manifest serves it.
///
/// This is the only shape in the system that carries plaintext the requesting
/// principal may not otherwise be entitled to read (§6.5.6 step 1), which is
/// why it is a named type rather than an anonymous tuple: every field on it is
/// a disclosure, and adding one has to be a visible diff.
#[derive(Debug, Clone)]
pub struct SealManifestItem {
    /// The claim.
    pub claim_id: Uuid,
    /// `claims.content`.
    pub content: String,
    /// `claims.labels`.
    pub labels: Vec<String>,
    /// `claims.properties`.
    pub properties: serde_json::Value,
    /// Every `claim_versions` row for this claim.
    pub versions: Vec<SealManifestVersion>,
    /// Every `evidence` row for this claim.
    pub evidence: Vec<SealManifestEvidence>,
}

/// One `claim_versions` row in a seal manifest.
#[derive(Debug, Clone)]
pub struct SealManifestVersion {
    /// `claim_versions.id`.
    pub id: Uuid,
    /// `claim_versions.content`.
    pub content: String,
}

/// One `evidence` row in a seal manifest.
#[derive(Debug, Clone)]
pub struct SealManifestEvidence {
    /// `evidence.id`.
    pub id: Uuid,
    /// `evidence.raw_content`, which is nullable in the schema.
    pub raw_content: Option<String>,
    /// `evidence.properties`.
    pub properties: serde_json::Value,
}

/// One claim's ciphertext, as the client returns it to seal-commit.
///
/// Every field is REQUIRED. §6.5.4's TCB is a set, and §6.5.6 says a commit
/// missing any member of it is refused rather than partially applied — a
/// half-sealed claim reports success while the plaintext is one `pg_dump`
/// away. The `Option`s that would let a caller omit a field are therefore
/// absent from the type, and the version/evidence completeness check that the
/// type cannot express is [`PrivatizationRepository::seal_tcb_shape_conn`]'s.
#[derive(Debug, Clone)]
pub struct SealCommitItem {
    /// The claim.
    pub claim_id: Uuid,
    /// `EncryptedPayload::to_bytes()` of the padded `content`.
    pub content_ct: Vec<u8>,
    /// `EncryptedPayload::to_bytes()` of the padded `labels`.
    pub labels_ct: Vec<u8>,
    /// `EncryptedPayload::to_bytes()` of the padded `properties`.
    pub properties_ct: Vec<u8>,
    /// BLAKE3 over `content_ct`. Exactly 32 bytes, per
    /// `claims_content_hash_length`.
    pub content_hash: Vec<u8>,
    /// One entry per `claim_versions` row.
    pub versions: Vec<SealCommitVersion>,
    /// One entry per `evidence` row.
    pub evidence: Vec<SealCommitEvidence>,
}

/// One sealed `claim_versions` row.
#[derive(Debug, Clone)]
pub struct SealCommitVersion {
    /// `claim_versions.id`.
    pub id: Uuid,
    /// `EncryptedPayload::to_bytes()` of the padded version content.
    pub content_ct: Vec<u8>,
}

/// One sealed `evidence` row.
#[derive(Debug, Clone)]
pub struct SealCommitEvidence {
    /// `evidence.id`.
    pub id: Uuid,
    /// `EncryptedPayload::to_bytes()` of the padded `raw_content`.
    pub content_ct: Vec<u8>,
    /// `EncryptedPayload::to_bytes()` of the padded `properties`.
    pub properties_ct: Vec<u8>,
}

/// The version and evidence rows a seal-commit must cover for one claim.
///
/// Read from the database at commit time, never from the manifest the client
/// was served: a row inserted between the manifest and the commit would
/// otherwise survive the seal in plaintext, which is the shape of the defect
/// §6.5.4 was written to close.
#[derive(Debug, Clone)]
pub struct SealTcbShape {
    /// The claim.
    pub claim_id: Uuid,
    /// Every live `claim_versions.id` for it.
    pub version_ids: Vec<Uuid>,
    /// Every live `evidence.id` for it.
    pub evidence_ids: Vec<Uuid>,
}

/// One claim's ciphertext, as the unseal manifest serves it.
#[derive(Debug, Clone)]
pub struct UnsealManifestItem {
    /// The claim.
    pub claim_id: Uuid,
    /// The epoch every ciphertext on this item is bound to.
    pub epoch: i32,
    /// `claim_encryption.encrypted_content`.
    pub content_ct: Vec<u8>,
    /// `claim_encryption.encrypted_labels`.
    pub labels_ct: Option<Vec<u8>>,
    /// `claim_encryption.encrypted_properties`.
    pub properties_ct: Option<Vec<u8>>,
    /// `claim_version_encryption` rows.
    pub versions: Vec<SealCommitVersion>,
    /// `evidence_encryption` rows.
    pub evidence: Vec<SealCommitEvidence>,
}

/// One claim's restored plaintext, as the client returns it to unseal-commit.
#[derive(Debug, Clone)]
pub struct UnsealCommitItem {
    /// The claim.
    pub claim_id: Uuid,
    /// The restored `claims.content`.
    pub content: String,
    /// The restored `claims.content_hash`. Exactly 32 bytes.
    pub content_hash: Vec<u8>,
    /// The restored `claims.labels`.
    pub labels: Vec<String>,
    /// The restored `claims.properties`.
    pub properties: serde_json::Value,
    /// The restored `claim_versions` rows.
    pub versions: Vec<UnsealCommitVersion>,
    /// The restored `evidence` rows.
    pub evidence: Vec<UnsealCommitEvidence>,
}

/// One restored `claim_versions` row.
#[derive(Debug, Clone)]
pub struct UnsealCommitVersion {
    /// `claim_versions.id`.
    pub id: Uuid,
    /// The restored content.
    pub content: String,
}

/// One restored `evidence` row.
#[derive(Debug, Clone)]
pub struct UnsealCommitEvidence {
    /// `evidence.id`.
    pub id: Uuid,
    /// The restored `raw_content`.
    pub raw_content: Option<String>,
    /// The restored `properties`.
    pub properties: serde_json::Value,
}

/// Read-only selection and rendering for D4 privatization.
pub struct PrivatizationRepository;

impl PrivatizationRepository {
    // =====================================================================
    // PASS 1 — SELECTION. Unfiltered, by design and by necessity.
    // =====================================================================

    /// Walk the closure from `seeds` along `edge_types`.
    ///
    /// Refuses structural edge types before opening a statement, and refuses
    /// rather than truncates when the result would exceed `node_cap`.
    ///
    /// # Authority
    ///
    /// `viewer` must be a BYPASS viewer, and that is all this function checks —
    /// with a `debug_assert!`, so it is loud in tests and absent from a release
    /// build. [`crate::visibility::SystemReason::PrivatizationSelection`] is the
    /// reason a caller should mint it with, but the reason is the caller's
    /// until there is a persisted plan to attribute it to, and nothing here
    /// requires it. The marker in the statement renders to nothing for a bypass
    /// viewer; a `Scoped` viewer would narrow the walk, which is wrong but
    /// fails closed.
    ///
    /// # Errors
    ///
    /// [`SelectionRefusal`] for a bad request; [`DbError`] for a query fault.
    pub async fn select_closure(
        conn: &mut PgConnection,
        viewer: &Viewer,
        request: ClosureRequest<'_>,
    ) -> Result<Vec<SelectedClaim>, SelectionError> {
        debug_assert!(
            viewer.is_bypass(),
            "privatization selection must run unfiltered; a Scoped viewer here \
             under-selects and produces a plan that misses the rows it exists to find"
        );

        if request.seeds.is_empty() {
            return Err(SelectionRefusal::NoSeeds.into());
        }
        if request.max_depth <= 0 {
            return Err(SelectionRefusal::NonPositiveBound {
                parameter: "max_depth",
                value: request.max_depth,
            }
            .into());
        }
        if request.node_cap <= 0 {
            return Err(SelectionRefusal::NonPositiveBound {
                parameter: "node_cap",
                value: request.node_cap,
            }
            .into());
        }
        // FINAL-PLAN §3.1's two system ceilings. Checked AFTER positivity so a
        // negative bound still reports the more specific refusal, and BEFORE any
        // statement opens: an over-large request is refused rather than
        // attempted and truncated.
        if request.max_depth > MAX_TRAVERSAL_DEPTH {
            return Err(SelectionRefusal::DepthAboveSystemMaximum {
                requested: request.max_depth,
                maximum: MAX_TRAVERSAL_DEPTH,
            }
            .into());
        }
        if request.node_cap > MAX_NODE_CAP {
            return Err(SelectionRefusal::NodeCapAboveSystemMaximum {
                requested: request.node_cap,
                maximum: MAX_NODE_CAP,
            }
            .into());
        }
        for relationship in request.edge_types {
            if classify_edge_type(relationship) == EdgeTypeTier::Structural {
                return Err(SelectionRefusal::StructuralEdgeType {
                    relationship: relationship.clone(),
                }
                .into());
            }
        }

        // ASK FOR ONE MORE ROW THAN THE CAP ALLOWS. The SQL function's LIMIT has
        // no ORDER BY, so it cannot tell us it truncated; the only way to learn
        // that the honest answer does not fit is to leave room for the evidence.
        let probe_cap = request.node_cap.saturating_add(1);

        // THE JOIN IS A **LEFT** JOIN, AND THAT IS THE OVERFLOW PROBE'S CORRECTNESS.
        //
        // The join to `claims` does two things. It carries the visibility
        // marker (the function returns bare uuids and offers nothing to filter
        // on), and it identifies any id that names no live claim row. The
        // function's non-recursive term echoes `unnest(p_seeds)` back
        // unfiltered, so a seed the operator typed wrong arrives here as a row;
        // without the join it would become a plan item for an entity that does
        // not exist, and an apply would carry a row it can never resolve. (The
        // TRAVERSED ids are a different matter — `trigger_validate_edge_refs`
        // refuses an edge naming a nonexistent claim and deleting a claim
        // cascades its edges away, both measured, so the reachable source of an
        // unresolvable id is the seed list.)
        //
        // An INNER join would do both of those and silently break the cap
        // probe. Every id the function emits consumes one `LIMIT p_node_cap`
        // slot whether or not it resolves; an inner join then removes the
        // unresolved ones from `rows.len()`, so a probe window that was full —
        // i.e. the function may have truncated real rows — comes back looking
        // like a selection that fits. A LEFT join keeps `rows.len()` equal to
        // the function's own output cardinality, which is the number the cap
        // must be compared against, and the unresolved rows are discarded in
        // Rust afterwards.
        //
        // The predicate rides in the `ON` clause rather than a `WHERE`, because
        // a `WHERE` on the right-hand table would turn the LEFT join back into
        // an inner one and undo the paragraph above.
        let sql = viewer.splice(
            r#"
            SELECT k.claim_id, k.depth, k.via, (c.id IS NOT NULL) AS live
              FROM public.epigraph_privatization_closure($1, $2, $3, $4, $5) k
              LEFT JOIN public.claims c
                     ON c.id = k.claim_id
                        /* {VISIBILITY:c} */
             ORDER BY k.depth, k.claim_id
            "#,
            6,
        );

        let mut query = sqlx::query_as::<_, (Uuid, i32, Option<String>, bool)>(&sql)
            .bind(request.seeds)
            .bind(request.edge_types)
            .bind(request.direction.as_str())
            .bind(request.max_depth)
            .bind(probe_cap);
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        let rows = query
            .fetch_all(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;

        // Measured on the FUNCTION's cardinality, before the unresolved rows
        // are dropped. A refusal here is fail-closed rather than exact: when
        // the probe window is full we cannot tell a selection that genuinely
        // overflows from one padded by ids that resolve to nothing, and in
        // both cases we cannot prove the function did not truncate.
        if i64::try_from(rows.len()).unwrap_or(i64::MAX) > i64::from(request.node_cap) {
            return Err(SelectionRefusal::NodeCapExceeded {
                node_cap: request.node_cap,
            }
            .into());
        }

        Ok(rows
            .into_iter()
            .filter(|(_, _, _, live)| *live)
            .map(|(claim_id, depth, via, _)| SelectedClaim {
                claim_id,
                depth,
                via: via.unwrap_or_else(|| "seed".to_string()),
            })
            .collect())
    }

    /// Expand `anchors` by the mandatory content-lineage hull, to a FIXED POINT.
    ///
    /// See the module doc: one call to `epigraph_content_lineage_hull` leaves
    /// the `step_lineage_id` sibling arm one hop deep and cuts a `supersedes`
    /// chain at 64 hops. Re-seeding until a round adds nothing closes both.
    ///
    /// Anchors are processed in ascending depth bands, so a hull member reached
    /// from two anchors takes the lower depth.
    ///
    /// The returned vector contains the anchors themselves plus everything the
    /// hull added, sorted by `(depth, claim_id)`.
    ///
    /// # Authority
    ///
    /// Unfiltered, exactly as [`Self::select_closure`]: a hull narrowed to what
    /// the actor can read would leave a public successor pointing at a
    /// privatized predecessor, which is the existence oracle the hull exists to
    /// prevent.
    ///
    /// # Errors
    ///
    /// [`SelectionRefusal::NodeCapExceeded`] when the closed hull is larger
    /// than `node_cap`; [`DbError`] for a query fault.
    pub async fn select_content_lineage_hull(
        conn: &mut PgConnection,
        viewer: &Viewer,
        anchors: &[SelectedClaim],
        node_cap: i32,
    ) -> Result<Vec<SelectedClaim>, SelectionError> {
        debug_assert!(
            viewer.is_bypass(),
            "the content-lineage hull must run unfiltered; a filtered hull leaves a \
             public successor pointing at a privatized predecessor"
        );

        if node_cap <= 0 {
            return Err(SelectionRefusal::NonPositiveBound {
                parameter: "node_cap",
                value: node_cap,
            }
            .into());
        }

        // id -> (depth, via). First writer wins, which is what makes the
        // ascending-band loop below resolve ties to the lowest anchor depth.
        let mut selected: BTreeMap<Uuid, (i32, String)> = BTreeMap::new();
        for anchor in anchors {
            selected
                .entry(anchor.claim_id)
                .or_insert_with(|| (anchor.depth, anchor.via.clone()));
        }

        // THE CAP IS CHECKED BEFORE THE LOOP AS WELL AS INSIDE IT. The in-loop
        // check only fires on a round that ADDED something, so a call whose
        // anchors already exceed `node_cap` and whose hull grows by nothing
        // would otherwise return `Ok` with more items than the cap allows —
        // which is not what `# Errors` promises. Unreachable through
        // `select_closure`, which caps first; reachable for any other caller.
        if i64::try_from(selected.len()).unwrap_or(i64::MAX) > i64::from(node_cap) {
            return Err(SelectionRefusal::NodeCapExceeded { node_cap }.into());
        }

        let mut bands: Vec<i32> = anchors.iter().map(|a| a.depth).collect();
        bands.sort_unstable();
        bands.dedup();

        for band in bands {
            // Everything at this depth or shallower is a legitimate anchor for
            // this band; starting from the whole prefix rather than the exact
            // band lets a chain that leaves and re-enters the band close.
            let mut frontier: Vec<Uuid> = selected
                .iter()
                .filter(|(_, (depth, _))| *depth <= band)
                .map(|(id, _)| *id)
                .collect();

            loop {
                let discovered = Self::hull_round(conn, viewer, &frontier).await?;
                let mut added = Vec::new();
                for (claim_id, via) in discovered {
                    // Vacant-only: an id already present keeps the depth and the
                    // provenance the first (shallowest) band gave it. Every round
                    // re-seeds the function with ids it already knows, and the
                    // function labels every seed it is handed `seed`, so an
                    // unconditional insert would relabel a closure-reached claim
                    // as a seed and contradict `depth`'s own `0 = seed` rule.
                    if let std::collections::btree_map::Entry::Vacant(slot) =
                        selected.entry(claim_id)
                    {
                        slot.insert((band, via));
                        added.push(claim_id);
                    }
                }
                if added.is_empty() {
                    break;
                }
                if i64::try_from(selected.len()).unwrap_or(i64::MAX) > i64::from(node_cap) {
                    return Err(SelectionRefusal::NodeCapExceeded { node_cap }.into());
                }
                frontier.extend(added);
            }
        }

        let mut out: Vec<SelectedClaim> = selected
            .into_iter()
            .map(|(claim_id, (depth, via))| SelectedClaim {
                claim_id,
                depth,
                via,
            })
            .collect();
        out.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.claim_id.cmp(&b.claim_id)));
        Ok(out)
    }

    /// One call to the SQL hull. Returns `(claim_id, via)` for everything it
    /// reaches, including the seeds it was given (labelled `seed`).
    async fn hull_round(
        conn: &mut PgConnection,
        viewer: &Viewer,
        seeds: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        if seeds.is_empty() {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            r#"
            SELECT h.claim_id, h.via
              FROM public.epigraph_content_lineage_hull($1) h
              JOIN public.claims c ON c.id = h.claim_id
             WHERE true
               /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut query = sqlx::query_as::<_, (Uuid, Option<String>)>(&sql).bind(seeds);
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        let rows = query
            .fetch_all(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        Ok(rows
            .into_iter()
            .map(|(claim_id, via)| (claim_id, via.unwrap_or_else(|| "seed".to_string())))
            .collect())
    }

    /// Count edges with exactly ONE endpoint in the selection, by relationship.
    ///
    /// These are the edges a privatization would leave straddling a tenancy
    /// boundary. The result is a COUNT and carries no edge ids, so it is safe
    /// to show to any authorized caller regardless of what they can read —
    /// which is why it runs unfiltered.
    ///
    /// # What it does not count
    ///
    /// `claim`-to-`claim` edges only. `edges` endpoints are polymorphic, so an
    /// edge with a non-claim endpoint — evidence, a frame, a perspective — is
    /// outside this survey even when it genuinely straddles the boundary. The
    /// number is a subtotal and a caller must name it as one.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn boundary_edge_counts(
        conn: &mut PgConnection,
        viewer: &Viewer,
        selected: &[Uuid],
    ) -> Result<Vec<BoundaryEdgeCount>, DbError> {
        debug_assert!(
            viewer.is_bypass(),
            "the boundary survey must run unfiltered or it undercounts the edges it exists to report"
        );
        if selected.is_empty() {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            r#"
            SELECT lower(e.relationship::text) AS relationship, count(*) AS n
              FROM public.edges e
             WHERE e.source_type = 'claim' AND e.target_type = 'claim'
               AND (e.source_id = ANY($1)) <> (e.target_id = ANY($1))
               /* {EDGE_VISIBILITY:e} */
             GROUP BY lower(e.relationship::text)
             ORDER BY lower(e.relationship::text)
            "#,
            2,
        );
        let mut query = sqlx::query_as::<_, (String, i64)>(&sql).bind(selected);
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        let rows = query
            .fetch_all(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        Ok(rows
            .into_iter()
            .map(|(relationship, count)| BoundaryEdgeCount {
                relationship,
                count,
            })
            .collect())
    }

    /// How many distinct authors would lose read access to their OWN claims.
    ///
    /// An author loses access when a claim they wrote moves into a group they
    /// are not a live member of. This drives the dual-control acknowledgement
    /// (`privatization_plans.acknowledge_author_loss`), so it must count every
    /// affected author and not merely the ones the actor can see.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn authors_losing_own_claims(
        conn: &mut PgConnection,
        viewer: &Viewer,
        selected: &[Uuid],
        target_group_id: Uuid,
    ) -> Result<i64, DbError> {
        debug_assert!(
            viewer.is_bypass(),
            "the author-loss count drives dual control and must be complete"
        );
        if selected.is_empty() {
            return Ok(0);
        }
        let sql = viewer.splice(
            r#"
            SELECT count(DISTINCT c.agent_id)
              FROM public.claims c
             WHERE c.id = ANY($1)
               AND NOT EXISTS (
                     SELECT 1 FROM public.group_memberships m
                      WHERE m.group_id = $2
                        AND m.agent_id = c.agent_id
                        AND m.revoked_at IS NULL)
               /* {VISIBILITY:c} */
            "#,
            3,
        );
        let mut query = sqlx::query_scalar::<_, i64>(&sql)
            .bind(selected)
            .bind(target_group_id);
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        query
            .fetch_one(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })
    }

    /// How many of `candidates` name a live claim, counted WITHOUT the actor's
    /// authority.
    ///
    /// This is the denominator `not_visible_to_actor` is computed against:
    /// the caller subtracts [`Self::visible_previews`]'s length from it and
    /// reports the difference as a number. Deliberately the same table and the
    /// same candidate set as the rendering pass, differing only in authority,
    /// so the subtraction compares like with like.
    ///
    /// **There is no such caller in this crate.** The subtraction is performed
    /// only in `privatization_authz.rs`, which proves the two passes disagree
    /// in the required direction; the field itself is produced by whichever
    /// slice assembles a preview object. This module supplies the two halves,
    /// not the assembled answer.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn count_selected(
        conn: &mut PgConnection,
        viewer: &Viewer,
        candidates: &[Uuid],
    ) -> Result<i64, DbError> {
        debug_assert!(
            viewer.is_bypass(),
            "the item count is the denominator of not_visible_to_actor; counting it under the \
             actor's authority would report a plan smaller than the one that will be applied"
        );
        if candidates.is_empty() {
            return Ok(0);
        }
        let sql = viewer.splice(
            r#"
            SELECT count(*)
              FROM public.claims c
             WHERE c.id = ANY($1)
               /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut query = sqlx::query_scalar::<_, i64>(&sql).bind(candidates);
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        query
            .fetch_one(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })
    }

    /// Which NOT-traversed relationships would have extended the selection.
    ///
    /// Computed by looking one hop out from the selection along every
    /// relationship the request did **not** name, and counting the claims that
    /// would have been added. This is the acceptance clause's "omitted-edge-type
    /// warning": an operator who privatizes along `derived_from` alone should be
    /// told that 40 claims hang off `decomposes_to`, not discover it afterwards.
    ///
    /// Structural types are excluded from the warning: they are refused as
    /// traversals, so reporting them as a missed opportunity would invite the
    /// one request this layer will not answer.
    ///
    /// # Two deliberate deviations, both fail-loud rather than fail-quiet
    ///
    /// * FINAL-PLAN §6.5.2 restricts this warning to the RESTATEMENT tier.
    ///   This implementation reports every non-structural, non-traversed
    ///   relationship, so the epistemic tier (`supports`, `contradicts`, …)
    ///   appears too. It over-reports rather than under-reports, and the
    ///   operator-facing decision is "should I have traversed this?", which is
    ///   a real question for an epistemic type even though the default is off.
    ///   A caller that wants the plan's narrower list can filter on
    ///   [`classify_edge_type`].
    /// * Like [`Self::boundary_edge_counts`], this is a `claim`-to-`claim`
    ///   survey; non-claim endpoints are not reported.
    ///
    /// `would_add` counts DISTINCT far endpoints that resolve to a live claim
    /// row, which is the same population [`Self::select_closure`] would
    /// actually add. Today the join to `claims` cannot change the number —
    /// `trigger_validate_edge_refs` refuses an edge naming a nonexistent claim
    /// and deleting a claim cascades its edges away — so it buys agreement
    /// rather than a correction: the two functions mean the same thing by "an
    /// id", and a later change to either guard cannot make them disagree
    /// silently.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn omitted_edge_types(
        conn: &mut PgConnection,
        viewer: &Viewer,
        selected: &[Uuid],
        traversed: &[String],
    ) -> Result<Vec<OmittedEdgeTypeWarning>, DbError> {
        debug_assert!(
            viewer.is_bypass(),
            "the omitted-edge-type warning must be complete to be worth showing"
        );
        if selected.is_empty() {
            return Ok(Vec::new());
        }
        let traversed_lower: Vec<String> =
            traversed.iter().map(|t| t.to_ascii_lowercase()).collect();
        let structural: Vec<String> = STRUCTURAL_EDGE_TYPES
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        let sql = viewer.splice(
            r#"
            SELECT lower(e.relationship::text) AS relationship,
                   count(DISTINCT oc.id) AS n
              FROM public.edges e
              JOIN public.claims oc
                ON oc.id = CASE WHEN e.source_id = ANY($1)
                                THEN e.target_id ELSE e.source_id END
                   /* {VISIBILITY:oc} */
             WHERE e.source_type = 'claim' AND e.target_type = 'claim'
               AND (e.source_id = ANY($1)) <> (e.target_id = ANY($1))
               AND NOT (lower(e.relationship::text) = ANY($2))
               AND NOT (lower(e.relationship::text) = ANY($3))
               /* {EDGE_VISIBILITY:e} */
             GROUP BY lower(e.relationship::text)
             ORDER BY lower(e.relationship::text)
            "#,
            4,
        );
        let mut query = sqlx::query_as::<_, (String, i64)>(&sql)
            .bind(selected)
            .bind(&traversed_lower)
            .bind(&structural);
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        let rows = query
            .fetch_all(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        Ok(rows
            .into_iter()
            .map(|(relationship, would_add)| OmittedEdgeTypeWarning {
                relationship,
                would_add,
            })
            .collect())
    }

    // =====================================================================
    // PASS 2 — RENDERING. The actor's own authority, and nothing wider.
    // =====================================================================

    /// The subset of `candidates` the ACTOR may read, with a short content
    /// preview.
    ///
    /// This is the only function in this module that returns claim CONTENT, and
    /// the only one whose `viewer` is expected to be `Scoped`. An id absent
    /// from the result is an id the actor may not learn: the caller reports the
    /// difference as a count (`not_visible_to_actor`) and never as a list, a
    /// placeholder or a redaction sentinel.
    ///
    /// # Authority
    ///
    /// `viewer` must be `Scoped`, and that is a RUNTIME refusal
    /// ([`SelectionRefusal::BypassViewerInRenderingPass`]) rather than a
    /// `debug_assert!`. The selection side asserts, because its fail-open is a
    /// visibly wrong plan; this side refuses, because `debug_assertions` is off
    /// in a release profile and an assert that is not compiled is not a control
    /// on the one path where a fail-open cannot be taken back.
    ///
    /// # Which connection
    ///
    /// Either an app connection or the maintenance one. On an app connection
    /// the RLS policy is a second, independent filter; on the maintenance
    /// connection `epigraph_bypass()` is true and the spliced predicate is the
    /// ONLY control. The predicate alone is sufficient — it is written to match
    /// the trailing disjuncts of migration 077's `claims_tenancy` `USING`
    /// clause, so it is never weaker — but a caller that already holds the
    /// maintenance connection from the selection pass is choosing the
    /// single-control configuration and should know it.
    ///
    /// # Errors
    ///
    /// [`SelectionRefusal::BypassViewerInRenderingPass`] for a bypass viewer;
    /// [`DbError`] for a query fault.
    pub async fn visible_previews(
        conn: &mut PgConnection,
        viewer: &Viewer,
        candidates: &[Uuid],
    ) -> Result<Vec<ItemPreview>, SelectionError> {
        if viewer.is_bypass() {
            return Err(SelectionRefusal::BypassViewerInRenderingPass.into());
        }
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            r#"
            SELECT c.id, left(c.content, $2) AS preview
              FROM public.claims c
             WHERE c.id = ANY($1)
               /* {VISIBILITY:c} */
             ORDER BY c.id
            "#,
            3,
        );
        let mut query = sqlx::query_as::<_, (Uuid, String)>(&sql)
            .bind(candidates)
            .bind(PREVIEW_CHARS);
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        let rows = query
            .fetch_all(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        Ok(rows
            .into_iter()
            .map(|(claim_id, preview)| ItemPreview { claim_id, preview })
            .collect())
    }

    /// How many of `candidates` the ACTOR can read.
    ///
    /// The rendering-pass twin of [`Self::count_selected`]: same table, same
    /// candidate set, differing only in authority. The preview reports the
    /// DIFFERENCE between the two as `not_visible_to_actor` — a count, with no
    /// ids and no content (sec F7).
    ///
    /// It returns no ids at all, so nothing here needs a limit; the refusal on a
    /// bypass viewer is kept anyway, because a bypass viewer would make this
    /// equal to [`Self::count_selected`] and the reported difference would be a
    /// flat zero — a preview that claimed the actor could read everything.
    ///
    /// # Errors
    ///
    /// [`SelectionRefusal::BypassViewerInRenderingPass`] for a bypass viewer;
    /// [`DbError`] for a query fault.
    pub async fn count_visible(
        conn: &mut PgConnection,
        viewer: &Viewer,
        candidates: &[Uuid],
    ) -> Result<i64, SelectionError> {
        if viewer.is_bypass() {
            return Err(SelectionRefusal::BypassViewerInRenderingPass.into());
        }
        if candidates.is_empty() {
            return Ok(0);
        }
        let sql = viewer.splice(
            r#"
            SELECT count(*)
              FROM public.claims c
             WHERE c.id = ANY($1)
               /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut query = sqlx::query_scalar::<_, i64>(&sql).bind(candidates);
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        query
            .fetch_one(&mut *conn)
            .await
            .map_err(|source| SelectionError::Db(DbError::QueryFailed { source }))
    }

    /// The boundary edge IDS the actor may read.
    ///
    /// The counterpart to [`Self::boundary_edge_counts`]: that one counts every
    /// boundary edge, this one names only the edges the actor's own viewer
    /// admits. `edges` has TWO owning groups since migration 072, so this read
    /// carries the `EDGE_VISIBILITY` marker — the single-owner spelling would
    /// satisfy every lint and still show a cross-group edge to a principal in
    /// only one of its two owning groups.
    ///
    /// Like [`Self::boundary_edge_counts`], this surveys `claim`-to-`claim`
    /// edges only; see that function's doc for what that excludes.
    ///
    /// # Authority and bounds
    ///
    /// `viewer` must be `Scoped`, refused at RUNTIME for the reason
    /// [`Self::visible_previews`] gives. `limit` is a SAMPLE bound, not a cap
    /// in the module-header sense: a non-positive `limit` means "no sample" and
    /// yields an empty vector rather than being rounded up to one id, and the
    /// upper bound of 1000 exists so a caller cannot turn a sample into the
    /// whole boundary by asking for a large number.
    ///
    /// # Errors
    ///
    /// [`SelectionRefusal::BypassViewerInRenderingPass`] for a bypass viewer;
    /// [`DbError`] for a query fault.
    pub async fn visible_boundary_edges(
        conn: &mut PgConnection,
        viewer: &Viewer,
        selected: &[Uuid],
        limit: i64,
    ) -> Result<Vec<Uuid>, SelectionError> {
        if viewer.is_bypass() {
            return Err(SelectionRefusal::BypassViewerInRenderingPass.into());
        }
        if selected.is_empty() || limit <= 0 {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            r#"
            SELECT e.id
              FROM public.edges e
             WHERE e.source_type = 'claim' AND e.target_type = 'claim'
               AND (e.source_id = ANY($1)) <> (e.target_id = ANY($1))
               /* {EDGE_VISIBILITY:e} */
             ORDER BY e.id
             LIMIT $2
            "#,
            3,
        );
        let mut query = sqlx::query_scalar::<_, Uuid>(&sql)
            .bind(selected)
            .bind(limit.min(MAX_BOUNDARY_EDGE_SAMPLE));
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        query
            .fetch_all(&mut *conn)
            .await
            .map_err(|source| SelectionError::Db(DbError::QueryFailed { source }))
    }

    // =====================================================================
    // THE COMPOSED ENTRY POINT — the only door a request path may use.
    // =====================================================================

    /// Run the whole selection pass and return it as an [`UnfilteredSelection`].
    ///
    /// Closure first, then the mandatory content-lineage hull over the closure's
    /// output, iterated to a fixed point. The result is the frozen id set a plan
    /// stores, and it is returned in a wrapper whose only id-bearing exits take
    /// the ACTOR's viewer or write into a FORCE-protected table.
    ///
    /// # Authority and connection
    ///
    /// `viewer` must be a BYPASS viewer minted with
    /// [`crate::visibility::SystemReason::PrivatizationSelection`], and `conn`
    /// must be the MAINTENANCE connection: `EXECUTE` on both migration-080
    /// selection functions is granted to `epigraph_maintenance` alone. The
    /// reason cannot be checked from a `Viewer` — it is not carried on the value
    /// — so this is a contract on the caller, and
    /// `crates/epigraph-api/src/routes/privatization.rs` is the one production
    /// caller that honours it.
    ///
    /// # A statement timeout is applied to `conn`, and it is not decoration
    ///
    /// FINAL-PLAN's PR-18 acceptance clause 1 requires a 17-seed / depth-3
    /// preview to return "within `statement_timeout`". The maintenance
    /// connection carries whatever bound its pool was built with, which for the
    /// api server is none; the closure and the hull are the two statements in
    /// the system that can walk the whole edge corpus, and the hull is a LOOP of
    /// them. So the bound is applied here, on the connection, before the first
    /// statement, through the same `epigraph_db::apply_statement_timeout` the
    /// job pool uses. An overrun surfaces as `57014 query_canceled`, which
    /// [`SelectionError::Db`] carries to the route as a 500 rather than as a
    /// silently truncated plan.
    ///
    /// # THE BOUND IS SCOPED TO THIS CALL, AND THAT COST A REVISION TO GET RIGHT
    ///
    /// `apply_statement_timeout` issues a SESSION-scope `SET`, not a `SET
    /// LOCAL` — there is no enclosing transaction here to make `LOCAL` mean
    /// anything. An earlier revision of this function left the bound in place
    /// and justified it with "the caller drops the connection back to the pool,
    /// and every pool issues its own `after_connect` settings". That
    /// justification is WRONG: `after_connect` fires once when a physical
    /// connection is established, not on each checkout, and `ScopedPool`'s
    /// `after_release` scrub covers the three tenancy GUCs and nothing else. So
    /// the bound outlived the request and applied to whatever ran next on that
    /// connection — and `ScopedPool::maintenance_inner()` falls back to the
    /// APPLICATION pool when no dedicated maintenance pool is attached, which is
    /// what every fixture does. A privatization preview could therefore pin a
    /// 30-second cap on a request-path connection.
    ///
    /// So the prior value is read with `SHOW`, and restored on EVERY exit
    /// including the error ones. `SHOW` returns a unit-suffixed string (`0`,
    /// `30s`, `45min`), which is why the restore quotes it rather than
    /// interpolating a bare token.
    ///
    /// # Errors
    ///
    /// [`SelectionRefusal`] for a bad request — including FINAL-PLAN §3.1's two
    /// ceilings; [`DbError`] for a query fault or a timeout.
    pub async fn select(
        conn: &mut PgConnection,
        viewer: &Viewer,
        request: ClosureRequest<'_>,
        statement_timeout: std::time::Duration,
    ) -> Result<UnfilteredSelection, SelectionError> {
        let previous = crate::pool::read_statement_timeout(conn)
            .await
            .map_err(|source| SelectionError::Db(DbError::QueryFailed { source }))?;

        crate::pool::apply_statement_timeout(conn, statement_timeout)
            .await
            .map_err(|source| SelectionError::Db(DbError::QueryFailed { source }))?;

        let selected = match Self::select_closure(conn, viewer, request).await {
            Ok(closure) => {
                Self::select_content_lineage_hull(conn, viewer, &closure, request.node_cap).await
            }
            Err(e) => Err(e),
        };

        // Restored BEFORE the `?` on `selected`, so a refusal or a timeout
        // leaves the connection exactly as it was found.
        let restored = crate::pool::restore_statement_timeout(conn, &previous).await;

        let hulled = selected?;
        restored.map_err(|source| SelectionError::Db(DbError::QueryFailed { source }))?;
        Ok(UnfilteredSelection { items: hulled })
    }

    // =====================================================================
    // PERSISTED PLANS — reads, through migration 087's SELECT policies.
    //
    // None of the three takes a `Viewer`, and that is the honest shape rather
    // than an omission: `privatization_plans` and `privatization_plan_items`
    // have no `visibility` column and no `owner_group_id`, so there is no
    // predicate to splice. Their tenancy is 087's policy — instance admin AND
    // group admin of the plan's target group — and the CONNECTION is what
    // selects it. Give them a stamped app connection; see the module doc.
    //
    // ALL THREE ARE NAMED `*_conn`, AND THE SUFFIX IS THE CONTROL, NOT A STYLE.
    // `visibility_lint.rs::every_conn_taking_repo_fn_takes_a_viewer_or_is_exempt`
    // selects on the NAME, so a viewer-less `&mut PgConnection` read called
    // anything else escapes it, escapes the viewer-spending lint (which selects
    // on the parameter list mentioning `Viewer`) and escapes the executor lint
    // (which selects on `PgExecutor`) — three registers, none of them reached.
    // An earlier revision of this slice shipped these three without the suffix
    // and was therefore registered nowhere. They are now enumerated in
    // `CONN_WITHOUT_VIEWER` with their reasons, so the next author who widens
    // one of them into a join over `claims` has to edit a register to do it.
    // =====================================================================

    /// One plan by id, or `None` when the connection's principal may not read it.
    ///
    /// **A missing row and a denied row are the same answer here, deliberately.**
    /// RLS filters rather than errors, so a plan the caller does not administer
    /// is absent, and the route turns that into a 404. Distinguishing the two
    /// would be an existence oracle over every other admin's plans, which is one
    /// half of the cross-tenant read §6.5.2 records.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn load_plan_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
    ) -> Result<Option<PlanRow>, DbError> {
        sqlx::query_as::<_, PlanRow>(&format!(
            "SELECT {PLAN_ROW_COLUMNS}
               FROM public.privatization_plans p
              WHERE p.id = $1"
        ))
        .bind(plan_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Every plan the connection's principal may read, newest first.
    ///
    /// # TWO INDEPENDENT CONTROLS, WHICH IS A REVERSAL OF THIS FUNCTION'S FIRST
    /// SHAPE
    ///
    /// §6.5.7's `GET /plans` row says "rows filtered to plans whose target group
    /// the caller administers". An earlier revision left that filter entirely to
    /// 087's policy and argued the case in this doc: "a handler-side copy of a
    /// policy predicate is a second place for it to drift, and the policy is the
    /// one that binds." The argument is real but it is outweighed here, and the
    /// two sibling reads of this same table settle it —
    /// [`Self::load_plan_conn`]'s callers re-check FINAL-PLAN §6.6 against the
    /// plan's own `target_group_id` on a maintenance connection, so `get_plan`
    /// and `get_plan_items` each carry a second control and this one carried
    /// none. It is also the shape [`Self::visible_previews`] documents as
    /// correct: a spliced predicate PLUS the policy, each an independent filter.
    ///
    /// The rows this endpoint serves are the ones FINAL-PLAN §6.5.2 names — one
    /// admin's view of another admin's plans — so a single event that stops the
    /// policy from binding on this connection (an unstamped connection, a future
    /// `NO FORCE`, a dropped policy, a fixture reusing a privileged role) had
    /// nothing behind it. The `WHERE` below is therefore the §6.6 conjunction
    /// expressed with the SAME session helpers 087 uses, not a paraphrase of it:
    /// they cannot drift apart without the helpers themselves changing, which
    /// changes both at once.
    ///
    /// **The consequence, stated:** this statement now returns NOTHING on a
    /// connection whose `epigraph.principal_id` is unstamped, including a
    /// `#[sqlx::test]` superuser pool, and nothing on a bypass connection —
    /// there is deliberately no `epigraph_bypass()` arm, because no maintenance
    /// caller lists plans and adding one would re-open exactly what this closes.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn list_plans_conn(
        conn: &mut PgConnection,
        state: Option<&str>,
        target_group_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<PlanRow>, DbError> {
        sqlx::query_as::<_, PlanRow>(&format!(
            r#"
            SELECT {PLAN_ROW_COLUMNS}
              FROM public.privatization_plans p
             WHERE ($1::text IS NULL OR p.state = $1)
               AND ($2::uuid IS NULL OR p.target_group_id = $2)
               AND (SELECT public.epigraph_is_instance_admin(
                             (SELECT public.epigraph_principal_id())))
               AND public.epigraph_is_group_admin(p.target_group_id)
             ORDER BY p.created_at DESC, p.id
             LIMIT $3
            "#
        ))
        .bind(state)
        .bind(target_group_id)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// One page of a plan's frozen item set, positionally.
    ///
    /// The rows carry entity ids, so a caller MUST re-render them under the
    /// actor's own viewer before serialising — 087's policy establishes that the
    /// caller administers the plan's target group, which is not the same
    /// property as being able to read each selected claim. `entity_id` reaching
    /// this function is exactly the "complete index of every private entity id"
    /// migration 082's header names; [`Self::visible_previews`] is what decides
    /// which of them may be spoken aloud.
    ///
    /// # WHY THE PAGE IS AN OFFSET AND NOT A KEYSET
    ///
    /// The first revision paged with a keyset — `(kind, entity_id) > ($2, $3)`
    /// over the same `ORDER BY`. That made an ENTITY ID the ordering key of a
    /// read whose whole point is that the caller may be permitted to see only a
    /// COUNT of some of those entities, in both directions: the id had to leave
    /// the process to become the next page's token, and the next request had to
    /// be allowed to choose one. Neither is compatible with
    /// `not_visible_to_actor`, which exists precisely because some rows on this
    /// page must never be named.
    ///
    /// An offset is safe here for a reason specific to this table rather than as
    /// a general preference: the item set is FROZEN at plan creation, this table
    /// has no DELETE policy under `FORCE` and its only INSERT is the freeze, and
    /// the cardinality is already disclosed to this same caller as
    /// `privatization_plans.item_count`. So the set cannot shift under a reader,
    /// there is no skipped-row hazard, and the offset discloses nothing the plan
    /// row did not.
    ///
    /// **Migration 088 adds an UPDATE policy and the argument survives it,
    /// deliberately checked rather than assumed.** What 088 lets the apply
    /// handler move is `state`, `applied_at` and `error`. The `ORDER BY` is
    /// `(kind, entity_id)`, neither of which is writable by any policy, so a
    /// concurrent apply changes what a page SAYS and never which rows are on it.
    /// A keyset over `state` would not have that property, which is a second
    /// reason not to reintroduce one.
    ///
    /// A negative `offset` is a Postgres error, so the CALLER must reject one
    /// before it reaches here; `routes/privatization.rs::parse_cursor` does.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn load_plan_items_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<PlanItemRow>, DbError> {
        sqlx::query_as::<_, PlanItemRow>(
            r#"
            SELECT i.kind, i.entity_id, i.depth, i.via, i.state
              FROM public.privatization_plan_items i
             WHERE i.plan_id = $1
             ORDER BY i.kind, i.entity_id
             OFFSET $2
             LIMIT $3
            "#,
        )
        .bind(plan_id)
        .bind(offset)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Create the plan row, COMPLETE, on the MAINTENANCE connection.
    ///
    /// # Why the row is inserted already `previewed`, and not updated into it
    ///
    /// The natural shape — INSERT `state='selecting'`, run the selection, UPDATE
    /// the digest and counts and move to `previewed` — was IMPOSSIBLE when this
    /// function was written: migration 087 covered SELECT and INSERT only, and
    /// under `FORCE` an uncovered command is denied to EVERY role, bypass
    /// included.
    ///
    /// **Migration 088 has since added the UPDATE policy, so the shape is now
    /// merely wrong rather than impossible, and the argument for writing the row
    /// COMPLETE is worth restating because the mechanical obstacle is gone.**
    /// `plan_digest` and `item_count` describe the frozen set. A row that exists
    /// with a placeholder digest is a row another connection can read — 087's
    /// SELECT policy admits it the instant it commits — and a `previewed` plan
    /// whose digest does not describe its items is exactly what
    /// `apply`'s staleness check exists to refuse. Writing it once, after the
    /// selection, means that window never opens.
    ///
    /// The `approve`/`apply`/`abort`/`revert` transitions are
    /// [`Self::transition_plan_conn`]'s, and each is conditional on the state it
    /// expects to find for the same reason.
    ///
    /// 087's INSERT arm is `epigraph_bypass()` only, and 080 REVOKEs INSERT on
    /// this table from `epigraph_app`, so this cannot succeed anywhere else.
    /// Migration 081's `epigraph_privatization_plan_guard` fires on the INSERT
    /// and enforces the target group's 24-hour maturity and two-other-live-admins
    /// plurality in the database; the HTTP layer checks the same two conditions
    /// first so the refusal is a 403 with a reason rather than a raw SQLSTATE.
    ///
    /// # It returns `created_at` as well as `id`, and that is not convenience
    ///
    /// `expires_at` is DERIVED (`created_at + 4h`) because migration 080 stores
    /// no such column. A caller that derived it from its own `Utc::now()` would
    /// report a different TTL endpoint on `POST /plans` than `GET /plans/:id`
    /// serves for the same row, by the width of the freeze and the rendering
    /// pass. Returning the persisted timestamp gives both surfaces ONE base.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault — including the guard's `RAISE`, which the
    /// route maps to a 403.
    pub async fn create_previewed_plan(
        conn: &mut PgConnection,
        new: NewPlan<'_>,
    ) -> Result<(Uuid, chrono::DateTime<chrono::Utc>), DbError> {
        sqlx::query_as::<_, (Uuid, chrono::DateTime<chrono::Utc>)>(
            r#"
            INSERT INTO public.privatization_plans
                   (state, mode, target_group_id, selector, on_conflict, pad_to,
                    created_by, plan_digest, item_count, authors_losing_count)
            VALUES ('previewed', $1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, created_at
            "#,
        )
        .bind(new.mode)
        .bind(new.target_group_id)
        .bind(new.selector)
        .bind(new.on_conflict)
        .bind(new.pad_to)
        .bind(new.created_by)
        .bind(new.plan_digest)
        .bind(new.item_count)
        .bind(new.authors_losing_count)
        .fetch_one(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    // =====================================================================
    // APPLY / REVERT — the plan state machine, and the batch mutation.
    //
    // Everything below runs on the MAINTENANCE connection and is unreachable
    // from any other. Two independent reasons, and both are load-bearing:
    //
    //   * migration 080 REVOKEs INSERT, UPDATE and DELETE on both plan tables
    //     FROM `epigraph_app`, and
    //   * migration 088's UPDATE policies on both tables have a single
    //     `epigraph_bypass()` / `epigraph_definer_bypass()` disjunct.
    //
    // AND NONE OF THAT IS THE AUTHORIZATION. On this connection
    // `epigraph_bypass()` is true, so every RLS `WITH CHECK`, the
    // `writable_groups` gate and 074's declassification guard are things this
    // code can satisfy at will. FINAL-PLAN §6.5.5's re-validation in the job
    // handler is what decides whether a plan may move, and these functions are
    // the primitives it decides WITH. A caller that skips the re-validation and
    // calls `transition_plan_conn` directly gets an unapproved, stale-digest
    // privatization with no error — which is why the handler carries the
    // re-read `FOR UPDATE` and this module carries none of it.
    //
    // NAMED `*_conn` TO THE LAST ONE. `visibility_lint.rs`'s conn lint selects
    // on the SUFFIX, so a viewer-less connection-taking repo function called
    // anything else is invisible to it, to the viewer-spending lint and to the
    // executor lint at once. Each is enumerated in `CONN_WITHOUT_VIEWER` with
    // its reason.
    // =====================================================================

    /// Re-read a plan `FOR UPDATE`, for the handler's re-validation.
    ///
    /// The row lock is the point: FINAL-PLAN §6.5.5 requires the six conditions
    /// to be checked against a row nothing else can move between the check and
    /// the state flip. `FOR UPDATE` and not `FOR NO KEY UPDATE`, because the
    /// flip that follows is an UPDATE of `state`.
    ///
    /// Returns `None` when no such plan exists. On a stamped app connection it
    /// would also return `None` for a plan 087's SELECT policy hides, which is
    /// why this must be given the maintenance connection: a handler that read a
    /// filtered `None` would abort a legitimate plan.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault, including `55P03 lock_not_available` when
    /// the caller has set a `lock_timeout` and another transaction holds the row.
    pub async fn load_plan_for_update_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
    ) -> Result<Option<PlanRow>, DbError> {
        sqlx::query_as::<_, PlanRow>(&format!(
            "SELECT {PLAN_ROW_COLUMNS}
               FROM public.privatization_plans p
              WHERE p.id = $1
                FOR UPDATE"
        ))
        .bind(plan_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Move a plan through its state machine.
    ///
    /// One function rather than five, because all five arms are the same
    /// decision — "this plan may now be in that state" — and splitting them
    /// spreads the guard conditions over five `WHERE` clauses that then drift.
    /// Every arm is CONDITIONAL on the state it expects to find, and returns the
    /// affected row count so the caller can tell "moved" from "someone else
    /// moved it first" without a second read.
    ///
    /// # The guards live in the `WHERE`, not in the caller
    ///
    /// [`PlanTransition::Approve`] refuses a plan that is not `previewed` or
    /// that already carries an approver, so a double approval is a zero row
    /// count rather than a silent overwrite of the first approver's identity.
    /// [`PlanTransition::Dispatch`] refuses any state outside `from_states`, so
    /// two concurrent `apply` calls cannot both flip a plan to `applying` and
    /// enqueue two jobs against it.
    ///
    /// # What this does NOT check
    ///
    /// The four-eyes rule and the approver's group-admin status. Those are
    /// migration 080's `pp_four_eyes` CHECK and 081's
    /// `epigraph_privatization_approver_guard`, which bind this connection too —
    /// a trigger and a constraint are not RLS and `epigraph_bypass()` does not
    /// reach them. The route checks them first so the refusal carries a reason;
    /// the database is what makes the refusal true.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault, including `23514` from `pp_four_eyes` and
    /// `42501` from the approver guard.
    pub async fn transition_plan_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
        transition: PlanTransition<'_>,
    ) -> Result<u64, DbError> {
        let result = match transition {
            PlanTransition::Approve { approver } => {
                sqlx::query(
                    r#"
                    UPDATE public.privatization_plans
                       SET approved_by = $2, approved_at = now(),
                           state = 'approved', updated_at = now()
                     WHERE id = $1 AND state = 'previewed' AND approved_by IS NULL
                    "#,
                )
                .bind(plan_id)
                .bind(approver)
                .execute(&mut *conn)
                .await
            }
            PlanTransition::Dispatch {
                dispatched_by,
                to_state,
                from_states,
            } => {
                sqlx::query(
                    r#"
                    UPDATE public.privatization_plans
                       SET state = $3, dispatched_by = $2,
                           cursor_kind = NULL, cursor_depth = NULL, cursor_id = NULL,
                           updated_at = now()
                     WHERE id = $1 AND state = ANY($4)
                    "#,
                )
                .bind(plan_id)
                .bind(dispatched_by)
                .bind(to_state)
                .bind(from_states)
                .execute(&mut *conn)
                .await
            }
            PlanTransition::Cursor { kind, depth, id } => {
                sqlx::query(
                    r#"
                    UPDATE public.privatization_plans
                       SET cursor_kind = $2, cursor_depth = $3, cursor_id = $4,
                           updated_at = now()
                     WHERE id = $1
                    "#,
                )
                .bind(plan_id)
                .bind(kind)
                .bind(depth)
                .bind(id)
                .execute(&mut *conn)
                .await
            }
            PlanTransition::Drift { ids } => {
                sqlx::query(
                    r#"
                    UPDATE public.privatization_plans
                       SET drift_ids = $2, updated_at = now()
                     WHERE id = $1
                    "#,
                )
                .bind(plan_id)
                .bind(ids)
                .execute(&mut *conn)
                .await
            }
            PlanTransition::Finish { state, from_states } => {
                sqlx::query(
                    r#"
                    UPDATE public.privatization_plans
                       SET state = $2, updated_at = now()
                     WHERE id = $1
                       AND (cardinality($3::text[]) = 0 OR state = ANY($3))
                    "#,
                )
                .bind(plan_id)
                .bind(state)
                .bind(from_states)
                .execute(&mut *conn)
                .await
            }
        };
        result
            .map(|r| r.rows_affected())
            .map_err(|source| DbError::QueryFailed { source })
    }

    /// Recompute the plan digest FROM THE FROZEN ITEMS, at dispatch time.
    ///
    /// FINAL-PLAN §6.5.5 is explicit that the handler compares the stored
    /// `plan_digest` against "a digest recomputed from `privatization_plan_items`
    /// at dispatch time" rather than trusting the stored value. Reading the
    /// stored value twice and comparing it with itself is the shape that passes
    /// a test and checks nothing.
    ///
    /// The ordering here does not matter: [`Self::plan_digest`] sorts and
    /// dedupes, so the digest is a property of the SET.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn frozen_digest_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
    ) -> Result<[u8; 32], DbError> {
        let rows = sqlx::query_as::<_, (String, Uuid)>(
            r#"
            SELECT i.kind, i.entity_id
              FROM public.privatization_plan_items i
             WHERE i.plan_id = $1
            "#,
        )
        .bind(plan_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(Self::plan_digest(&rows))
    }

    /// Is `agent_id` a LIVE `role='admin'` member of `group_id`?
    ///
    /// FINAL-PLAN §6.5.5 requires this to be re-checked at dispatch, "because
    /// membership can be revoked between approve and dispatch". Migration 081's
    /// approver guard enforces it on the approving UPDATE and cannot enforce it
    /// afterwards; this is the dispatch-time half.
    ///
    /// Written as a direct `group_memberships` read rather than through
    /// `epigraph_is_group_admin`, whose `EXECUTE` is granted to
    /// `epigraph_maintenance` alone and which reads the SESSION principal rather
    /// than an argument — the question here is about the APPROVER, who is not
    /// the session principal on a job connection.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn is_live_group_admin_conn(
        conn: &mut PgConnection,
        group_id: Uuid,
        agent_id: Uuid,
    ) -> Result<bool, DbError> {
        sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM public.group_memberships m
                 WHERE m.group_id = $1
                   AND m.agent_id = $2
                   AND m.role = 'admin'
                   AND m.revoked_at IS NULL)
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Take the ONE global privatization advisory lock and bound the batch.
    ///
    /// # Why one global lock and not one per plan (ops F12)
    ///
    /// `privatization_one_active_per_group` is unique on `target_group_id`, so
    /// two plans against DIFFERENT groups can be in flight at once and can touch
    /// the same boundary `edges` rows in opposite orders. `ClaimRepository::consolidate`
    /// independently takes `SELECT … FROM claims … FOR UPDATE` and then rewrites
    /// the edge set — the opposite lock order to this batch. Deepest-first
    /// guarantees the downward-closure invariant, not lock order. FINAL-PLAN
    /// §6.5.5's fix is one global lock, and there is no stated need for
    /// concurrent plans.
    ///
    /// `pg_advisory_xact_lock` and not the session form: the lock must be
    /// released by the COMMIT that ends the batch, including the commit that
    /// happens when a `kill -9` closes the connection.
    ///
    /// # The two `SET LOCAL` bounds
    ///
    /// `lock_timeout = '3s'` and `statement_timeout = '60s'`, both from
    /// §6.5.5's ops-F11 correction. They are `LOCAL`, so they end with the
    /// transaction rather than outliving it on a pooled connection — the hazard
    /// [`Self::select`]'s doc records at length for the session-scope spelling.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault. A `55P03` here means another privatization
    /// batch holds the lock, which is a retry rather than a refusal.
    pub async fn begin_batch_conn(conn: &mut PgConnection) -> Result<(), DbError> {
        // ORDER MATTERS. `lock_timeout` is set BEFORE the advisory lock is
        // taken, or the very first thing this function does is an unbounded
        // wait — which is the wait the bound exists for.
        for statement in [
            "SET LOCAL lock_timeout = '3s'",
            "SET LOCAL statement_timeout = '60s'",
            "SELECT pg_advisory_xact_lock(hashtext('epigraph.privatization'))",
        ] {
            sqlx::query(statement)
                .execute(&mut *conn)
                .await
                .map_err(|source| DbError::QueryFailed { source })?;
        }
        Ok(())
    }

    /// One batch of a plan's remaining work, LOCKED.
    ///
    /// # `FOR UPDATE`, never `SKIP LOCKED`
    ///
    /// FINAL-PLAN §6.5.5 says so in those words, and the reason is that every
    /// item must be processed exactly once. `SKIP LOCKED` would silently leave
    /// a contended item `pending` while the plan advanced to `applied`, which is
    /// a privatization that reports success over a public claim.
    ///
    /// # The order IS the invariant
    ///
    /// `deepest_first` selects `ORDER BY depth DESC` for apply and
    /// `ORDER BY depth ASC` for revert. §6.5.5: at every commit boundary the
    /// private set is closed downward under the content-derivation relation, so
    /// a `kill -9` leaves a downward-closed prefix private rather than a private
    /// parent with public `decomposes_to` children. Revert is the mirror.
    ///
    /// The secondary keys (`kind`, `entity_id`) make the order TOTAL, which is
    /// what makes `privatization_resume.rs`'s "the final state equals the
    /// uninterrupted result" assertion meaningful rather than probabilistic.
    ///
    /// # `kind = 'claim'` matches what the batch can actually move
    ///
    /// [`UnfilteredSelection::freeze_into`] is the only writer of
    /// `privatization_plan_items` and writes `'claim'` for every row, so today
    /// this predicate excludes nothing. It is here because
    /// [`Self::mark_items_conn`], [`Self::restrict_claims_conn`] and
    /// [`Self::record_item_audit_conn`] all act on claims only: an item of some
    /// other kind would be selected by every batch, marked by none, and the
    /// batch loop would not terminate. PR-21's seal work is the slice most
    /// likely to add an `evidence` row, and a non-terminating loop holding the
    /// global privatization lock is the wrong way to find that out.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn next_batch_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
        item_state: &str,
        deepest_first: bool,
        limit: i64,
    ) -> Result<Vec<PlanWorkItem>, DbError> {
        let order = if deepest_first { "DESC" } else { "ASC" };
        sqlx::query_as::<_, PlanWorkItem>(&format!(
            "SELECT i.kind, i.entity_id, i.depth,
                    i.before_visibility, i.before_owner_group_id
               FROM public.privatization_plan_items i
              WHERE i.plan_id = $1 AND i.state = $2 AND i.kind = 'claim'
              ORDER BY i.depth {order}, i.kind, i.entity_id
              LIMIT $3
                FOR UPDATE"
        ))
        .bind(plan_id)
        .bind(item_state)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Move a batch of items to a terminal per-item state.
    ///
    /// `applied_at` is stamped on every transition and not only on `applied`,
    /// because the column records WHEN THE ITEM WAS LAST DECIDED; a `failed`
    /// item with a NULL timestamp is indistinguishable from one the handler
    /// never reached.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn mark_items_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
        kind: &str,
        entity_ids: &[Uuid],
        state: &str,
        error: Option<&str>,
    ) -> Result<u64, DbError> {
        if entity_ids.is_empty() {
            return Ok(0);
        }
        sqlx::query(
            r#"
            UPDATE public.privatization_plan_items i
               SET state = $4, applied_at = now(), error = $5
             WHERE i.plan_id = $1 AND i.kind = $2 AND i.entity_id = ANY($3)
            "#,
        )
        .bind(plan_id)
        .bind(kind)
        .bind(entity_ids)
        .bind(state)
        .bind(error)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// `restrict`: move a batch of claims into the target group.
    ///
    /// This is the whole of `restrict` mode. `content`, `content_tsv` and
    /// `embedding` are NOT in the statement — FINAL-PLAN §6.5.4's argument is
    /// that they are three columns of the same row, RLS is row-level, and the
    /// predicate that hides one hides all three atomically, so retaining them
    /// leaks nothing beyond what retaining `content` already leaks. That is what
    /// makes acceptance clause 6's bit-identity assertion true by construction
    /// rather than by care.
    ///
    /// # It fans out through a trigger, and that is deliberate
    ///
    /// Migration 072's statement-level `AFTER UPDATE` on `claims`
    /// (`epigraph_propagate_tenancy`) copies the new tenancy to seventeen
    /// derived tables, to `harvester_fragments` through the provenance join, and
    /// recomputes the `edges` meet over BOTH endpoints. So this one statement is
    /// the claims UPDATE, the evidence UPDATE and most of the boundary-edge meet
    /// §6.5.5 lists as three separate steps. **That is a correction to the plan,
    /// which was written before 072 existed in this form.** What the trigger
    /// does NOT do is widen an edge — its `NOT (e.visibility = 'group' AND
    /// m.v = 'public')` guard — which is why revert still needs
    /// [`Self::recompute_boundary_meet_conn`] explicitly.
    ///
    /// # The `IS DISTINCT FROM` guard is what makes a batch re-runnable
    ///
    /// A re-dispatched job that re-processes a committed batch changes no row,
    /// fires no trigger (072's firing gate is the same comparison) and writes no
    /// derived row. §6.5.5's ops-F11 correction requires exactly this, and the
    /// previous revision's claim that it already held was false for nine of ten
    /// propagation arms.
    ///
    /// # IT RETURNS THE IDS IT CHANGED, AND THE CALLER MUST USE THEM
    ///
    /// The same `IS DISTINCT FROM` guard that makes a batch re-runnable also
    /// means a row already sitting in the target group is a NO-OP for this plan.
    /// That is an ordinary thing for a plan frozen while the row was public to
    /// meet — two plans against the same target group with overlapping frozen
    /// sets is not a race, because `privatization_one_active_per_group` excludes
    /// only CONCURRENT running plans. An item marked `applied` on the strength
    /// of having been looked at rather than moved would make the revert path
    /// write this plan's selection-time pre-image over a row this plan never
    /// changed, and that pre-image is typically `public`. So the return value is
    /// the set of rows this statement actually moved, and
    /// `epigraph-jobs::privatization::run_batch` marks the remainder `skipped`.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn restrict_claims_conn(
        conn: &mut PgConnection,
        claim_ids: &[Uuid],
        target_group_id: Uuid,
    ) -> Result<Vec<Uuid>, DbError> {
        if claim_ids.is_empty() {
            return Ok(Vec::new());
        }
        sqlx::query_scalar::<_, Uuid>(
            r#"
            UPDATE public.claims c
               SET visibility = 'group', owner_group_id = $2, updated_at = now()
             WHERE c.id = ANY($1)
               AND (c.visibility IS DISTINCT FROM 'group'
                    OR c.owner_group_id IS DISTINCT FROM $2)
            RETURNING c.id
            "#,
        )
        .bind(claim_ids)
        .bind(target_group_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Restore a batch of claims to the tenancy the freeze recorded.
    ///
    /// The `before_visibility` / `before_owner_group_id` columns were read from
    /// `claims` in the same statement that wrote the item row
    /// ([`UnfilteredSelection::freeze_into`]), so this restores the state at
    /// SELECTION time rather than a value that has been round-tripping through
    /// Rust since.
    ///
    /// # IT RESTORES ONLY ROWS THAT STILL CARRY THIS PLAN'S STAMP
    ///
    /// `target_group_id` is not decoration and it is not an optimisation. The
    /// statement writes a SELECTION-TIME pre-image, and the only rows for which
    /// that pre-image is the right answer are the ones whose tenancy is still
    /// the one this plan wrote: `visibility = 'group'` and
    /// `owner_group_id = target_group_id`. A row that some other decision now
    /// owns — `privatization_one_active_per_group` is unique on
    /// `target_group_id`, not per claim, so a second plan against a different
    /// group is an ordinary thing to exist — is LEFT ALONE, and its tenancy is
    /// whatever that decision made it rather than whatever this plan saw before
    /// it. Fail-closed is the direction that matters here, because this is the
    /// one statement in the subsystem that can widen a row's tenancy.
    ///
    /// # It sets `epigraph.allow_declassify`, and that is the admin surface
    ///
    /// Migration 074's `claims_block_widening` refuses `group` → `public`
    /// unconditionally unless `epigraph.allow_declassify = 'yes'`, and its own
    /// comment names "the admin declassification surface" as the thing that sets
    /// it. This is that surface: a revert of a `restrict` plan is the ONE
    /// declassification the system performs, it is audited row by row, and it
    /// restores a value the database itself recorded rather than one a caller
    /// supplied.
    ///
    /// `SET LOCAL`, so the permission ends with the batch transaction. A session
    /// scope `SET` would leave it armed on a pooled connection for whatever ran
    /// next — the hazard [`Self::select`] documents for `statement_timeout`,
    /// with a far worse payload.
    ///
    /// **The sealed arm of that guard is NOT reachable from here and must not
    /// be.** It has no GUC override by design (sec F11), so a revert of a plan
    /// with a still-sealed item fails `42501` rather than producing a public row
    /// whose content is a stub. FINAL-PLAN ops-F13 requires the route to refuse
    /// such a plan with a 409 and a count BEFORE dispatch; this is the backstop.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn restore_claims_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
        claim_ids: &[Uuid],
        target_group_id: Uuid,
    ) -> Result<u64, DbError> {
        if claim_ids.is_empty() {
            return Ok(0);
        }
        sqlx::query("SET LOCAL epigraph.allow_declassify = 'yes'")
            .execute(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        sqlx::query(
            r#"
            UPDATE public.claims c
               SET visibility = i.before_visibility,
                   owner_group_id = i.before_owner_group_id,
                   updated_at = now()
              FROM public.privatization_plan_items i
             WHERE i.plan_id = $1
               AND i.kind = 'claim'
               AND i.entity_id = ANY($2)
               AND c.id = i.entity_id
               AND c.visibility = 'group'
               AND c.owner_group_id = $3
               AND (c.visibility IS DISTINCT FROM i.before_visibility
                    OR c.owner_group_id IS DISTINCT FROM i.before_owner_group_id)
            "#,
        )
        .bind(plan_id)
        .bind(claim_ids)
        .bind(target_group_id)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Re-run the endpoint meet over every edge touching this batch.
    ///
    /// FINAL-PLAN §6.5.3: an edge is visible iff both endpoints are, so edge
    /// tenancy is the MEET of its endpoints' tenancies. Migration 066(b) applies
    /// it on write and cannot apply it here, because it is `BEFORE INSERT OR
    /// UPDATE OF source_id, target_id` and privatization changes neither.
    ///
    /// # Why this exists when 072's propagation trigger already recomputes edges
    ///
    /// The trigger carries `AND NOT (e.visibility = 'group' AND m.v = 'public')`
    /// — it narrows an edge and refuses to widen one. That is right for a
    /// stamping trigger and wrong for a REVERT, which must be able to return an
    /// edge between two restored-public claims to `public`. Without this
    /// statement a reverted plan leaves its boundary edges `group`-visible
    /// forever, which is a privatization that reports itself undone and is not.
    /// It is idempotent, so running it on the apply path too costs a scan and
    /// buys agreement between the two directions.
    ///
    /// # `ORDER BY e.id` (ops F12)
    ///
    /// In the `ep` CTE, exactly where §6.5.3 puts it. Migration 072's header is
    /// right that an `ORDER BY` inside a subquery of `UPDATE … FROM` is a
    /// planner hint rather than a guaranteed lock order — which is why the
    /// GLOBAL advisory lock in [`Self::begin_batch_conn`] is the actual control
    /// and this is the cheap agreement with it.
    ///
    /// # The `COALESCE(…, 'public')` on a missing endpoint
    ///
    /// Deliberate, and §6.5.3 states it: an edge pointing at a `frame`, `agent`,
    /// `paper` or `task` has no tenancy, contributes `public` to the meet, and
    /// must never BLOCK a privatization.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn recompute_boundary_meet_conn(
        conn: &mut PgConnection,
        entity_ids: &[Uuid],
    ) -> Result<u64, DbError> {
        if entity_ids.is_empty() {
            return Ok(0);
        }
        sqlx::query(
            r#"
            WITH ep AS (
              SELECT e.id,
                     COALESCE(s.v, 'public')::text AS sv,
                     COALESCE(s.g, '00000000-0000-0000-0000-000000000000'::uuid) AS sg,
                     COALESCE(t.v, 'public')::text AS tv,
                     COALESCE(t.g, '00000000-0000-0000-0000-000000000000'::uuid) AS tg
                FROM public.edges e
                CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s
                CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t
               WHERE e.source_id = ANY($1) OR e.target_id = ANY($1)
               ORDER BY e.id
            ), meet AS (
              SELECT ep.id,
                     (CASE WHEN ep.sv = 'public' AND ep.tv = 'public'
                           THEN 'public' ELSE 'group' END)::varchar(16) AS v,
                     CASE WHEN ep.sv = 'public' AND ep.tv = 'public'
                               THEN '00000000-0000-0000-0000-000000000000'::uuid
                          WHEN ep.sv = 'public' THEN ep.tg
                          ELSE ep.sg END AS g,
                     CASE WHEN ep.sv = 'group' AND ep.tv = 'group' AND ep.sg <> ep.tg
                               THEN ep.tg ELSE NULL END AS co
                FROM ep
            )
            UPDATE public.edges e
               SET visibility = m.v, owner_group_id = m.g, co_owner_group_id = m.co
              FROM meet m
             WHERE m.id = e.id
               AND m.g IS NOT NULL
               AND (e.visibility, e.owner_group_id, e.co_owner_group_id)
                   IS DISTINCT FROM (m.v, m.g, m.co)
            "#,
        )
        .bind(entity_ids)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// How many of a `mode='seal'` plan's items are still sealed (ops F13).
    ///
    /// FINAL-PLAN §6.5.5 permits `revert` on a `mode='seal'` plan once every
    /// item is unsealed, and requires a `409` carrying this count otherwise.
    ///
    /// # THE `mode = 'seal'` PREDICATE IS THE WHOLE CORRECTNESS OF THIS COUNT
    ///
    /// `claim_encryption` is migration 060's table and belongs to the
    /// pre-existing encrypted-subgraph feature, which writes it from the
    /// ordinary claims surface and has nothing to do with D4 seal mode. Counting
    /// every encryption row joined to the plan's items would therefore refuse
    /// the revert of a `restrict` plan whose frozen set happens to contain an
    /// already-encrypted claim — a plan that sealed nothing, and whose full
    /// reversibility is the property §6.5.4 puts the most weight on. Nothing in
    /// the selection path filters such a claim out: `resolve_seeds` accepts any
    /// id, and the closure and the content-lineage hull both run under the
    /// bypass viewer.
    ///
    /// So the count is scoped to seal-mode plans. What is still NOT shipped is
    /// the seal path that could make it non-zero through the product — `seal`
    /// is PR-21's and `routes/privatization.rs::create_plan` returns `501` for
    /// it; `crates/epigraph-privacy` now supplies the encryptor, but nothing
    /// carries its output into these tables yet — so this
    /// returns 0 for every plan the ROUTE can create today. It is here so that
    /// the refusal arrives with the seal mode rather than after it.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn sealed_item_count_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
    ) -> Result<i64, DbError> {
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT count(*)
              FROM public.claim_encryption ce
              JOIN public.privatization_plan_items i
                ON i.entity_id = ce.claim_id AND i.kind = 'claim'
              JOIN public.privatization_plans p
                ON p.id = i.plan_id AND p.mode = 'seal'
             WHERE i.plan_id = $1
            "#,
        )
        .bind(plan_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    // =====================================================================
    // SEAL — the two-phase, client-driven ceremony (§6.5.6).
    //
    // THE SERVER NEVER HOLDS A KEY. Nothing below encrypts, decrypts or
    // derives; it serves plaintext to a key-holding admin, accepts ciphertext
    // back, and performs the §6.5.4 mutation. Every function here runs on the
    // MAINTENANCE connection, because the manifest must not be viewer-filtered
    // (a filtered manifest yields a partial commit, which §6.5.6 forbids) and
    // because the mutation writes rows whose RLS `WITH CHECK` the app role
    // cannot satisfy.
    // =====================================================================

    /// The group's `active` key epoch, or `None`.
    ///
    /// Seal binds every ciphertext to one epoch through
    /// `claim_encryption_epoch_fkey (group_id, epoch)`, and a group with no
    /// active epoch cannot be sealed into at all — which is a refusal, not a
    /// default. Returning `Option` rather than defaulting to `0` is the whole
    /// point: epoch `0` is a legal epoch, so a silent default would bind
    /// ciphertext to a key nobody rotated into.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn active_epoch_conn(
        conn: &mut PgConnection,
        group_id: Uuid,
    ) -> Result<Option<i32>, DbError> {
        sqlx::query_scalar::<_, i32>(
            r"
            SELECT e.epoch
              FROM public.group_key_epochs e
             WHERE e.group_id = $1 AND e.status = 'active'
             ORDER BY e.epoch DESC
             LIMIT 1
            ",
        )
        .bind(group_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// One page of a plan's SEAL MANIFEST: the plaintext §6.5.4 TCB.
    ///
    /// # This is the one response in the system that discloses plaintext the
    /// caller may not otherwise read, and it is deliberately not filtered
    ///
    /// §6.5.6 step 1 says so, and the reason is structural rather than a
    /// convenience: a manifest narrowed to what the actor can read yields a
    /// commit that covers only the rows the actor could see, and a commit that
    /// covers a subset of the TCB is the partial seal §6.5.4 forbids. The
    /// authority for the disclosure is §6.6's three conditions, checked in the
    /// route, plus the dual `security_events` / `privatization_audit` log the
    /// route writes — not a predicate here.
    ///
    /// `viewer` is nonetheless a real parameter and its marker is a real marker:
    /// a bypass viewer renders it to nothing, and a `Scoped` viewer passed here
    /// by mistake NARROWS the page rather than widening it. The failure
    /// direction is a manifest that is too small, which the commit's
    /// completeness check refuses loudly, rather than one that is too large,
    /// which nothing would catch.
    ///
    /// # Paging is keyset, on `claims.id`
    ///
    /// `after` is exclusive. An OFFSET page over a set that a concurrent seal is
    /// mutating skips rows; a keyset page over an immutable frozen item set does
    /// not.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn seal_manifest_page_conn(
        conn: &mut PgConnection,
        viewer: &Viewer,
        plan_id: Uuid,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<SealManifestItem>, DbError> {
        let sql = viewer.splice(
            r"
            SELECT c.id, c.content, c.labels, c.properties
              FROM public.claims c
              JOIN public.privatization_plan_items i
                ON i.entity_id = c.id AND i.kind = 'claim'
             WHERE i.plan_id = $1
               AND ($2::uuid IS NULL OR c.id > $2)
               /* {VISIBILITY:c} */
             ORDER BY c.id
             LIMIT $3
            ",
            4,
        );
        let mut query = sqlx::query_as::<_, (Uuid, String, Vec<String>, serde_json::Value)>(&sql)
            .bind(plan_id)
            .bind(after)
            .bind(limit);
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        let heads = query
            .fetch_all(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        if heads.is_empty() {
            return Ok(Vec::new());
        }
        let claim_ids: Vec<Uuid> = heads.iter().map(|(id, ..)| *id).collect();

        let versions = sqlx::query_as::<_, (Uuid, Uuid, String)>(
            r"
            SELECT v.claim_id, v.id, v.content
              FROM public.claim_versions v
             WHERE v.claim_id = ANY($1)
             ORDER BY v.claim_id, v.id
            ",
        )
        .bind(&claim_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        let evidence = sqlx::query_as::<_, (Uuid, Uuid, Option<String>, serde_json::Value)>(
            r"
            SELECT e.claim_id, e.id, e.raw_content, e.properties
              FROM public.evidence e
             WHERE e.claim_id = ANY($1)
             ORDER BY e.claim_id, e.id
            ",
        )
        .bind(&claim_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        Ok(heads
            .into_iter()
            .map(|(claim_id, content, labels, properties)| SealManifestItem {
                claim_id,
                content,
                labels,
                properties,
                versions: versions
                    .iter()
                    .filter(|(cid, ..)| *cid == claim_id)
                    .map(|(_, id, content)| SealManifestVersion {
                        id: *id,
                        content: content.clone(),
                    })
                    .collect(),
                evidence: evidence
                    .iter()
                    .filter(|(cid, ..)| *cid == claim_id)
                    .map(|(_, id, raw_content, properties)| SealManifestEvidence {
                        id: *id,
                        raw_content: raw_content.clone(),
                        properties: properties.clone(),
                    })
                    .collect(),
            })
            .collect())
    }

    /// The `claim_versions` and `evidence` rows a seal-commit must cover.
    ///
    /// Read at COMMIT time, on the same transaction as the mutation, so a row
    /// inserted between the manifest and the commit is caught rather than left
    /// behind in plaintext. §6.5.4's whole indictment of the previous revision
    /// is that it sealed a subset and reported success; comparing the commit
    /// against the manifest it served would reproduce that, because both would
    /// describe the same stale world.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn seal_tcb_shape_conn(
        conn: &mut PgConnection,
        claim_ids: &[Uuid],
    ) -> Result<Vec<SealTcbShape>, DbError> {
        if claim_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, (Uuid, Vec<Uuid>, Vec<Uuid>)>(
            r"
            SELECT ids.claim_id,
                   COALESCE(ARRAY(SELECT v.id FROM public.claim_versions v
                                   WHERE v.claim_id = ids.claim_id
                                   ORDER BY v.id), ARRAY[]::uuid[]) AS version_ids,
                   COALESCE(ARRAY(SELECT e.id FROM public.evidence e
                                   WHERE e.claim_id = ids.claim_id
                                   ORDER BY e.id), ARRAY[]::uuid[]) AS evidence_ids
              FROM unnest($1::uuid[]) AS ids(claim_id)
             ORDER BY ids.claim_id
            ",
        )
        .bind(claim_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(rows
            .into_iter()
            .map(|(claim_id, version_ids, evidence_ids)| SealTcbShape {
                claim_id,
                version_ids,
                evidence_ids,
            })
            .collect())
    }

    /// THE SEAL MUTATION. The whole §6.5.4 TCB, in the caller's transaction.
    ///
    /// Returns the ids it actually sealed. A claim that already carries a
    /// `claim_encryption` row is skipped whole — it is not re-sentinelled and
    /// its derived rows are not re-deleted — so a re-delivered commit is a
    /// no-op rather than a second, differently-keyed seal over a row whose
    /// plaintext is already gone.
    ///
    /// # Nine statements, one transaction, no partial seal
    ///
    /// The caller opens the transaction and the caller commits it. Every
    /// statement below is bounded to the ids the first one actually inserted,
    /// so the set that gets a ciphertext row and the set that loses its
    /// plaintext are the same set by construction rather than by care.
    ///
    /// What each statement is for:
    ///
    /// 1. `claim_encryption` — the ciphertext for `content`, `labels` and
    ///    `properties`. `encrypted_properties` is written here; the
    ///    `ClaimEncryptionRepository` shipped by an earlier slice cannot write
    ///    that column at all, which is why this INSERT is inline rather than a
    ///    call into it. Writing it here also keeps the whole ceremony on ONE
    ///    explicitly-acquired maintenance connection — the caller's — which is
    ///    the property the rest of this module holds and is worth more than the
    ///    two lines the reuse would have saved.
    /// 2. `claims` — the sentinel, the ciphertext hash, and the emptying of
    ///    every plaintext-derived column. **`embedding_3072` is nulled here and
    ///    is absent from §6.5.4's table.** It is a second, live
    ///    `vector(3072)` ANN column on the same row, written by the re-embed
    ///    path and read by recall at `centroid_dim=3072`; leaving it would keep
    ///    a plaintext-derived vector on a sealed claim, which is the exact
    ///    defect the plan's own audit clause was written to catch one column
    ///    over. `content_tsv` needs no statement — it is `GENERATED ALWAYS` and
    ///    follows `content`.
    /// 3. `claim_version_encryption` + 4. `claim_versions` — the complete
    ///    plaintext version history, which is the survivor §6.5.4 names first.
    /// 5. `evidence_encryption` + 6. `evidence` — including
    ///    `embedding_3072` again, and `privacy_tier`, which the plan's DDL for
    ///    this table omits and the applied schema requires.
    /// 7. The derived-extraction DELETEs, over
    ///    [`SEAL_DELETE_TABLES`].
    /// 8. `harvester_fragments`, through the provenance join. Not recoverable
    ///    on unseal, which the preview states.
    ///
    /// # Ordering: restrict first, then seal
    ///
    /// Statement 1 fires `claim_encryption_no_public_sealed` (migration 081),
    /// which raises `42501` on sealing a claim that is still
    /// `visibility='public'`. That is the backstop, not the control: the route
    /// refuses a plan that has not been applied. It is load-bearing anyway,
    /// because it is what makes the ordering an invariant of the database
    /// rather than of this function.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault. A `42501` from statement 1 is 081's guard
    /// refusing an unrestricted claim.
    pub async fn seal_claims_conn(
        conn: &mut PgConnection,
        group_id: Uuid,
        epoch: i32,
        items: &[SealCommitItem],
    ) -> Result<Vec<Uuid>, DbError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let claim_ids: Vec<Uuid> = items.iter().map(|i| i.claim_id).collect();
        let content_cts: Vec<Vec<u8>> = items.iter().map(|i| i.content_ct.clone()).collect();
        let labels_cts: Vec<Vec<u8>> = items.iter().map(|i| i.labels_ct.clone()).collect();
        let props_cts: Vec<Vec<u8>> = items.iter().map(|i| i.properties_ct.clone()).collect();
        let hashes: Vec<Vec<u8>> = items.iter().map(|i| i.content_hash.clone()).collect();

        // 1. The ciphertext row. ON CONFLICT DO NOTHING is what makes a
        //    re-delivered commit a no-op; the RETURNING set is what bounds
        //    every statement after it.
        let sealed: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
            r"
            INSERT INTO public.claim_encryption
                   (claim_id, group_id, epoch, privacy_tier,
                    encrypted_content, encrypted_labels, encrypted_properties)
            SELECT t.claim_id, $5, $6, $7, t.content_ct, t.labels_ct, t.props_ct
              FROM unnest($1::uuid[], $2::bytea[], $3::bytea[], $4::bytea[])
                AS t(claim_id, content_ct, labels_ct, props_ct)
            ON CONFLICT (claim_id) DO NOTHING
            RETURNING claim_id
            ",
        )
        .bind(&claim_ids)
        .bind(&content_cts)
        .bind(&labels_cts)
        .bind(&props_cts)
        .bind(group_id)
        .bind(epoch)
        .bind(SEALED_PRIVACY_TIER)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        if sealed.is_empty() {
            return Ok(Vec::new());
        }

        // 2. The claim itself.
        sqlx::query(&format!(
            r"
            UPDATE public.claims c
               SET content = {SEAL_CONTENT_SENTINEL},
                   content_hash = t.content_hash,
                   embedding = NULL,
                   embedding_3072 = NULL,
                   labels = ARRAY[]::text[],
                   properties = '{{}}'::jsonb,
                   updated_at = now()
              FROM unnest($1::uuid[], $2::bytea[]) AS t(claim_id, content_hash)
             WHERE c.id = t.claim_id AND c.id = ANY($3)
            "
        ))
        .bind(&claim_ids)
        .bind(&hashes)
        .bind(&sealed)
        .execute(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        // 3/4. Version history.
        let (version_ids, version_cts): (Vec<Uuid>, Vec<Vec<u8>>) = items
            .iter()
            .filter(|i| sealed.contains(&i.claim_id))
            .flat_map(|i| i.versions.iter().map(|v| (v.id, v.content_ct.clone())))
            .unzip();
        if !version_ids.is_empty() {
            sqlx::query(
                r"
                INSERT INTO public.claim_version_encryption
                       (claim_version_id, claim_id, group_id, epoch, encrypted_content)
                SELECT t.version_id, v.claim_id, $3, $4, t.content_ct
                  FROM unnest($1::uuid[], $2::bytea[]) AS t(version_id, content_ct)
                  JOIN public.claim_versions v ON v.id = t.version_id
                ON CONFLICT (claim_version_id) DO NOTHING
                ",
            )
            .bind(&version_ids)
            .bind(&version_cts)
            .bind(group_id)
            .bind(epoch)
            .execute(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;

            sqlx::query(&format!(
                r"
                UPDATE public.claim_versions v
                   SET content = {SEAL_VERSION_SENTINEL}
                 WHERE v.id = ANY($1)
                "
            ))
            .bind(&version_ids)
            .execute(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        }

        // 5/6. Evidence.
        let mut evidence_ids: Vec<Uuid> = Vec::new();
        let mut evidence_cts: Vec<Vec<u8>> = Vec::new();
        let mut evidence_prop_cts: Vec<Vec<u8>> = Vec::new();
        for item in items.iter().filter(|i| sealed.contains(&i.claim_id)) {
            for e in &item.evidence {
                evidence_ids.push(e.id);
                evidence_cts.push(e.content_ct.clone());
                evidence_prop_cts.push(e.properties_ct.clone());
            }
        }
        if !evidence_ids.is_empty() {
            sqlx::query(
                r"
                INSERT INTO public.evidence_encryption
                       (evidence_id, group_id, epoch, privacy_tier,
                        encrypted_content, encrypted_properties)
                SELECT t.evidence_id, $4, $5, $6, t.content_ct, t.props_ct
                  FROM unnest($1::uuid[], $2::bytea[], $3::bytea[])
                    AS t(evidence_id, content_ct, props_ct)
                ON CONFLICT (evidence_id) DO NOTHING
                ",
            )
            .bind(&evidence_ids)
            .bind(&evidence_cts)
            .bind(&evidence_prop_cts)
            .bind(group_id)
            .bind(epoch)
            .bind(SEALED_PRIVACY_TIER)
            .execute(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;

            sqlx::query(
                r"
                UPDATE public.evidence e
                   SET raw_content = $2,
                       embedding = NULL,
                       embedding_3072 = NULL,
                       properties = '{}'::jsonb
                 WHERE e.id = ANY($1)
                ",
            )
            .bind(&evidence_ids)
            .bind(SEAL_EVIDENCE_SENTINEL)
            .execute(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        }

        // 7. The derived extractions. Deleted, not encrypted.
        for table in SEAL_DELETE_TABLES {
            sqlx::query(&format!(
                "DELETE FROM public.{table} WHERE claim_id = ANY($1)"
            ))
            .bind(&sealed)
            .execute(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        }

        // 8. Harvester source text, through the provenance join. NOT restored
        //    by unseal, and the preview says so before the admin clicks.
        //
        //    DELIBERATELY NOT NARROWED TO FRAGMENTS CITED ONLY BY SEALED CLAIMS.
        //    `harvester_claim_provenance` is keyed `(claim_id, fragment_id)`, so
        //    one fragment can back several claims, and a fragment shared with a
        //    claim outside this plan is blanked for all of them. Adding a
        //    `NOT EXISTS (… p2.claim_id <> ALL($1))` guard would leave the
        //    SEALED claim's own source text sitting in the corpus in plaintext —
        //    the direction §6.5.4 calls worse than not sealing at all. The cost
        //    is borne by the other claim's provenance, which is a functional
        //    loss and not a confidentiality one, and `SEAL_UNRECOVERABLE` states
        //    it in the preview before the admin clicks.
        sqlx::query(
            r"
            UPDATE public.harvester_fragments f
               SET content_text = $2, context_window = NULL
              FROM public.harvester_claim_provenance p
             WHERE p.fragment_id = f.id AND p.claim_id = ANY($1)
            ",
        )
        .bind(&sealed)
        .bind(SEAL_EVIDENCE_SENTINEL)
        .execute(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        Ok(sealed)
    }

    /// One page of a plan's UNSEAL MANIFEST: ciphertext only.
    ///
    /// No `Viewer` and no marker, and — unlike the seal manifest — nothing here
    /// is a disclosure: every byte it returns is already ciphertext bound to a
    /// key the server does not hold. The authority is still §6.6's, checked in
    /// the route, because knowing WHICH claims are sealed is itself
    /// information; but there is no plaintext predicate to spend a viewer on.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn unseal_manifest_page_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<UnsealManifestItem>, DbError> {
        type Head = (Uuid, i32, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);
        let heads = sqlx::query_as::<_, Head>(
            r"
            SELECT ce.claim_id, ce.epoch, ce.encrypted_content,
                   ce.encrypted_labels, ce.encrypted_properties
              FROM public.claim_encryption ce
              JOIN public.privatization_plan_items i
                ON i.entity_id = ce.claim_id AND i.kind = 'claim'
             WHERE i.plan_id = $1
               AND ($2::uuid IS NULL OR ce.claim_id > $2)
             ORDER BY ce.claim_id
             LIMIT $3
            ",
        )
        .bind(plan_id)
        .bind(after)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        if heads.is_empty() {
            return Ok(Vec::new());
        }
        let claim_ids: Vec<Uuid> = heads.iter().map(|(id, ..)| *id).collect();

        let versions = sqlx::query_as::<_, (Uuid, Uuid, Vec<u8>)>(
            r"
            SELECT cve.claim_id, cve.claim_version_id, cve.encrypted_content
              FROM public.claim_version_encryption cve
             WHERE cve.claim_id = ANY($1)
             ORDER BY cve.claim_id, cve.claim_version_id
            ",
        )
        .bind(&claim_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        let evidence = sqlx::query_as::<_, (Uuid, Uuid, Vec<u8>, Option<Vec<u8>>)>(
            r"
            SELECT e.claim_id, ee.evidence_id, ee.encrypted_content,
                   ee.encrypted_properties
              FROM public.evidence_encryption ee
              JOIN public.evidence e ON e.id = ee.evidence_id
             WHERE e.claim_id = ANY($1)
             ORDER BY e.claim_id, ee.evidence_id
            ",
        )
        .bind(&claim_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        Ok(heads
            .into_iter()
            .map(
                |(claim_id, epoch, content_ct, labels_ct, properties_ct)| UnsealManifestItem {
                    claim_id,
                    epoch,
                    content_ct,
                    labels_ct,
                    properties_ct,
                    versions: versions
                        .iter()
                        .filter(|(cid, ..)| *cid == claim_id)
                        .map(|(_, id, ct)| SealCommitVersion {
                            id: *id,
                            content_ct: ct.clone(),
                        })
                        .collect(),
                    evidence: evidence
                        .iter()
                        .filter(|(cid, ..)| *cid == claim_id)
                        .map(|(_, id, ct, props)| SealCommitEvidence {
                            id: *id,
                            content_ct: ct.clone(),
                            properties_ct: props.clone().unwrap_or_default(),
                        })
                        .collect(),
                },
            )
            .collect())
    }

    /// The `claim_version_encryption` and `evidence_encryption` rows an
    /// unseal-commit must cover, for the claims that are actually sealed.
    ///
    /// The mirror of [`Self::seal_tcb_shape_conn`], and the asymmetry between
    /// the two is deliberate rather than an oversight: seal covers
    /// `claim_versions` — every PLAINTEXT row that exists — while unseal covers
    /// `claim_version_encryption` — every CIPHERTEXT row that exists. A version
    /// row inserted after the seal has plaintext and no ciphertext; unseal must
    /// neither demand it nor touch it, and reading the shape from the encryption
    /// tables is what makes that true by construction.
    ///
    /// A claim with no `claim_encryption` row is ABSENT from the result rather
    /// than present with empty arrays. The caller uses that to tell "already
    /// unsealed, so a re-delivered commit for it is a no-op" from "sealed with
    /// nothing to cover", which are the same shape and must not be the same
    /// decision.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn unseal_tcb_shape_conn(
        conn: &mut PgConnection,
        group_id: Uuid,
        claim_ids: &[Uuid],
    ) -> Result<Vec<SealTcbShape>, DbError> {
        if claim_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, (Uuid, Vec<Uuid>, Vec<Uuid>)>(
            r"
            SELECT ce.claim_id,
                   COALESCE(ARRAY(SELECT cve.claim_version_id
                                    FROM public.claim_version_encryption cve
                                   WHERE cve.claim_id = ce.claim_id
                                   ORDER BY cve.claim_version_id), ARRAY[]::uuid[]),
                   COALESCE(ARRAY(SELECT ee.evidence_id
                                    FROM public.evidence_encryption ee
                                    JOIN public.evidence e ON e.id = ee.evidence_id
                                   WHERE e.claim_id = ce.claim_id
                                   ORDER BY ee.evidence_id), ARRAY[]::uuid[])
              FROM public.claim_encryption ce
             WHERE ce.claim_id = ANY($1) AND ce.group_id = $2
             ORDER BY ce.claim_id
            ",
        )
        .bind(claim_ids)
        .bind(group_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(rows
            .into_iter()
            .map(|(claim_id, version_ids, evidence_ids)| SealTcbShape {
                claim_id,
                version_ids,
                evidence_ids,
            })
            .collect())
    }

    /// THE UNSEAL MUTATION. The mirror of [`Self::seal_claims_conn`].
    ///
    /// Returns the ids it restored.
    ///
    /// # Every statement is bound to `group_id` or to a restored claim
    ///
    /// The server cannot verify the plaintext it is handed: `content_hash` is
    /// BLAKE3 over the CIPHERTEXT on the seal path, the route's unseal-side hash
    /// check is self-consistent by construction, and the key that would settle
    /// the question is one the server never holds. The scoping predicates are
    /// therefore the whole of the protection, and there are two:
    ///
    /// * `claim_encryption.group_id = $6` on the head UPDATE. Not
    ///   belt-and-braces over the caller's plan-membership check: a claim can be
    ///   an item of one group's plan while its ciphertext is bound to another's,
    ///   and only this predicate answers that.
    /// * `t.claim_id` carried through the version and evidence `unnest`es, so a
    ///   row id is addressable only through the claim it actually belongs to.
    ///   Without it, one restored claim in a batch can rewrite another claim's
    ///   version or evidence text.
    ///
    /// # `content_tsv` has no statement, and that is the design
    ///
    /// It is `GENERATED ALWAYS AS (to_tsvector('english', content)) STORED`
    /// (migration 050), so restoring `content` restores it. §6.5.6 says it in
    /// those words: there is no tsvector code path to write.
    ///
    /// # The embedding is NOT restored here
    ///
    /// It cannot be — the server has no embedder on this path and the vector was
    /// destroyed by the seal, not stashed. The caller enqueues an
    /// `embedding_generation` job per restored claim (ops F14); until that job
    /// runs, the claim is embedding-less, which the CLAUDE.md audit reports as a
    /// live gap rather than hiding.
    ///
    /// # What unseal does NOT restore
    ///
    /// The deleted extractions and `harvester_fragments`' source text. Both are
    /// stated in the seal preview, and re-extraction is a separate, explicit
    /// operation.
    ///
    /// # The ciphertext DELETEs are keyed on what was RESTORED, not on the claim
    ///
    /// A commit that restores a claim's head but omits one of its version rows
    /// must not delete that row's ciphertext: the seal already destroyed the
    /// plaintext, so the ciphertext is the only remaining copy and the deletion
    /// is not reversible by anyone, key or no key. Keying the two derived
    /// DELETEs on the ids actually restored makes the worst case a STRANDED
    /// ciphertext row — still decryptable by a key-holder, out of the unseal
    /// manifest's reach until re-linked — rather than a destroyed one. The
    /// caller additionally refuses an incomplete cover outright
    /// ([`Self::unseal_tcb_shape_conn`]), so through the route this branch is
    /// unreachable; it is the repo function being correct on its own terms.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault. A `23514` here is
    /// `claims_content_not_empty` refusing a blank restore; the caller checks
    /// first so this is a backstop.
    pub async fn unseal_claims_conn(
        conn: &mut PgConnection,
        group_id: Uuid,
        items: &[UnsealCommitItem],
    ) -> Result<Vec<Uuid>, DbError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let claim_ids: Vec<Uuid> = items.iter().map(|i| i.claim_id).collect();
        let contents: Vec<String> = items.iter().map(|i| i.content.clone()).collect();
        let hashes: Vec<Vec<u8>> = items.iter().map(|i| i.content_hash.clone()).collect();
        let labels: Vec<serde_json::Value> = items
            .iter()
            .map(|i| serde_json::Value::from(i.labels.clone()))
            .collect();
        let properties: Vec<serde_json::Value> =
            items.iter().map(|i| i.properties.clone()).collect();

        // Bounded to rows that carry a ciphertext row BOUND TO THIS GROUP, so an
        // unseal can neither rewrite a claim that was never sealed nor reach a
        // claim sealed under another group's key.
        let restored: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
            r"
            UPDATE public.claims c
               SET content = t.content,
                   content_hash = t.content_hash,
                   labels = ARRAY(SELECT jsonb_array_elements_text(t.labels)),
                   properties = t.properties,
                   updated_at = now()
              FROM unnest($1::uuid[], $2::text[], $3::bytea[], $4::jsonb[], $5::jsonb[])
                AS t(claim_id, content, content_hash, labels, properties)
             WHERE c.id = t.claim_id
               AND EXISTS (SELECT 1 FROM public.claim_encryption ce
                            WHERE ce.claim_id = c.id AND ce.group_id = $6)
            RETURNING c.id
            ",
        )
        .bind(&claim_ids)
        .bind(&contents)
        .bind(&hashes)
        .bind(&labels)
        .bind(&properties)
        .bind(group_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        if restored.is_empty() {
            return Ok(Vec::new());
        }

        // `t.claim_id` is carried alongside the row id, and the UPDATE matches on
        // BOTH. A bare `v.id = t.version_id` would let one claim in the batch
        // address another claim's version row.
        let mut version_ids: Vec<Uuid> = Vec::new();
        let mut version_parents: Vec<Uuid> = Vec::new();
        let mut version_contents: Vec<String> = Vec::new();
        for item in items.iter().filter(|i| restored.contains(&i.claim_id)) {
            for v in &item.versions {
                version_ids.push(v.id);
                version_parents.push(item.claim_id);
                version_contents.push(v.content.clone());
            }
        }
        if !version_ids.is_empty() {
            sqlx::query(
                r"
                UPDATE public.claim_versions v
                   SET content = t.content
                  FROM unnest($1::uuid[], $2::uuid[], $3::text[])
                    AS t(version_id, claim_id, content)
                 WHERE v.id = t.version_id AND v.claim_id = t.claim_id
                ",
            )
            .bind(&version_ids)
            .bind(&version_parents)
            .bind(&version_contents)
            .execute(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        }

        let mut evidence_ids: Vec<Uuid> = Vec::new();
        let mut evidence_parents: Vec<Uuid> = Vec::new();
        let mut evidence_contents: Vec<Option<String>> = Vec::new();
        let mut evidence_props: Vec<serde_json::Value> = Vec::new();
        for item in items.iter().filter(|i| restored.contains(&i.claim_id)) {
            for e in &item.evidence {
                evidence_ids.push(e.id);
                evidence_parents.push(item.claim_id);
                evidence_contents.push(e.raw_content.clone());
                evidence_props.push(e.properties.clone());
            }
        }
        if !evidence_ids.is_empty() {
            sqlx::query(
                r"
                UPDATE public.evidence e
                   SET raw_content = t.raw_content,
                       properties = t.properties
                  FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::jsonb[])
                    AS t(evidence_id, claim_id, raw_content, properties)
                 WHERE e.id = t.evidence_id AND e.claim_id = t.claim_id
                ",
            )
            .bind(&evidence_ids)
            .bind(&evidence_parents)
            .bind(&evidence_contents)
            .bind(&evidence_props)
            .execute(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        }

        // The ciphertext rows go LAST. `claim_encryption` is the predicate the
        // claims UPDATE above bounds itself on, and it is also what
        // `epigraph_claims_block_widening` reads to refuse a declassification;
        // dropping it before the plaintext is back would open a window in which
        // a sealed claim has neither.
        if !version_ids.is_empty() {
            sqlx::query(
                "DELETE FROM public.claim_version_encryption \
                  WHERE claim_id = ANY($1) AND claim_version_id = ANY($2)",
            )
            .bind(&restored)
            .bind(&version_ids)
            .execute(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        }
        if !evidence_ids.is_empty() {
            sqlx::query(
                r"
                DELETE FROM public.evidence_encryption ee
                 USING public.evidence e
                 WHERE e.id = ee.evidence_id
                   AND e.claim_id = ANY($1)
                   AND ee.evidence_id = ANY($2)
                ",
            )
            .bind(&restored)
            .bind(&evidence_ids)
            .execute(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        }
        sqlx::query(
            "DELETE FROM public.claim_encryption WHERE claim_id = ANY($1) AND group_id = $2",
        )
        .bind(&restored)
        .bind(group_id)
        .execute(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        Ok(restored)
    }

    /// Which of `claim_ids` are FROZEN ITEMS of this plan.
    ///
    /// A seal-commit names claims; this is what proves each of them is one the
    /// plan actually selected and an operator actually approved. Returning the
    /// intersection rather than a boolean lets the caller name the count in its
    /// refusal without a second round trip, and without echoing the ids of rows
    /// that are not in the plan.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn plan_contains_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
        claim_ids: &[Uuid],
    ) -> Result<Vec<Uuid>, DbError> {
        if claim_ids.is_empty() {
            return Ok(Vec::new());
        }
        sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT i.entity_id
              FROM public.privatization_plan_items i
             WHERE i.plan_id = $1 AND i.kind = 'claim' AND i.entity_id = ANY($2)
             ORDER BY i.entity_id
            ",
        )
        .bind(plan_id)
        .bind(claim_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Append one `privatization_audit` row per entity for a seal or unseal.
    ///
    /// # It writes `before_sealed` / `after_sealed`, which nothing else does
    ///
    /// Migration 082 created those two columns for exactly this and PR-21 is
    /// their first writer. `record_item_audit_conn`'s projection describes a
    /// TENANCY transition — `before_visibility` to `after_visibility` — and a
    /// seal changes neither: the claim was already `visibility='group'` before
    /// the ceremony began, because 081 refuses to seal a public claim. Reusing
    /// that function would therefore write an audit row asserting a visibility
    /// change that did not occur, which is worse than no row.
    ///
    /// Set-based over the whole batch, for the reason
    /// [`Self::record_item_audit_conn`] gives: 500 round trips inside a
    /// transaction holding the global privatization lock is not an audit trail,
    /// it is a lock-wait.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn record_seal_audit_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
        actor_agent_id: Uuid,
        action: &str,
        entity_ids: &[Uuid],
        sealed_after: bool,
        correlation_id: Option<&str>,
    ) -> Result<(), DbError> {
        if entity_ids.is_empty() {
            return Ok(());
        }
        sqlx::query(
            r"
            INSERT INTO public.privatization_audit
                   (plan_id, actor_agent_id, action, kind, entity_id,
                    before_visibility, before_owner_group_id, before_sealed,
                    after_visibility, after_owner_group_id, after_sealed,
                    correlation_id)
            SELECT $1, $2, $3, 'claim', c.id,
                   c.visibility, c.owner_group_id, NOT $5,
                   c.visibility, c.owner_group_id, $5,
                   $6
              FROM public.claims c
             WHERE c.id = ANY($4)
             ORDER BY c.id
            ",
        )
        .bind(plan_id)
        .bind(actor_agent_id)
        .bind(action)
        .bind(entity_ids)
        .bind(sealed_after)
        .bind(correlation_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// How many of a group's sealed rows are still bound to a NON-active epoch.
    ///
    /// The reseal handler's completion test (§6.7 point 3). A rotation retires
    /// epoch N and creates N+1 but re-encrypts nothing, so every
    /// `claim_encryption` row stays bound to N through
    /// `claim_encryption_epoch_fkey`. Zero here means the ceremony is finished
    /// and `groups.reseal_required_at` may be cleared; non-zero means it is not,
    /// and no amount of server-side work can make it so.
    ///
    /// # A group with NO active epoch counts every ciphertext row as stale
    ///
    /// The `active` CTE is then empty, `(SELECT epoch FROM active)` is NULL and
    /// `IS DISTINCT FROM NULL` is true for every row, so the flag cannot clear.
    /// That is the intended reading rather than an accident: a group whose only
    /// epochs are `retiring` or `retired` has no key to re-seal ONTO, so the
    /// ceremony genuinely is unfinished. A group that answers a rotation by
    /// unsealing everything still clears, because the count is then zero for
    /// want of rows rather than for want of an epoch.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn stale_epoch_seal_count_conn(
        conn: &mut PgConnection,
        group_id: Uuid,
    ) -> Result<i64, DbError> {
        sqlx::query_scalar::<_, i64>(
            r"
            WITH active AS (
                SELECT e.epoch FROM public.group_key_epochs e
                 WHERE e.group_id = $1 AND e.status = 'active'
                 ORDER BY e.epoch DESC LIMIT 1
            )
            SELECT (SELECT count(*) FROM public.claim_encryption ce
                     WHERE ce.group_id = $1
                       AND ce.epoch IS DISTINCT FROM (SELECT epoch FROM active))
                 + (SELECT count(*) FROM public.claim_version_encryption cve
                     WHERE cve.group_id = $1
                       AND cve.epoch IS DISTINCT FROM (SELECT epoch FROM active))
                 + (SELECT count(*) FROM public.evidence_encryption ee
                     WHERE ee.group_id = $1
                       AND ee.epoch IS DISTINCT FROM (SELECT epoch FROM active))
            ",
        )
        .bind(group_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Clear `groups.reseal_required_at`.
    ///
    /// **The only writer of that column back to NULL.** PR-20's rotation sets
    /// it and deliberately does not clear it, because rotation moves no
    /// `claim_encryption` row; clearing it on rotation would report a re-seal
    /// that did not happen. Its one caller is
    /// `epigraph_jobs::privatization::PrivatizationResealHandler`, which calls
    /// it only after [`Self::stale_epoch_seal_count_conn`] returns zero.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn clear_reseal_required_conn(
        conn: &mut PgConnection,
        group_id: Uuid,
    ) -> Result<u64, DbError> {
        sqlx::query(
            r"
            UPDATE public.groups g
               SET reseal_required_at = NULL, updated_at = now()
             WHERE g.id = $1 AND g.reseal_required_at IS NOT NULL
            ",
        )
        .bind(group_id)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Enqueue the apply/revert job, on the connection that flipped the plan.
    ///
    /// # Why the route enqueues through a repo function and not through the job
    /// queue's own client
    ///
    /// FINAL-PLAN §6.5.5 says it plainly — "the route enqueues through a repo
    /// function on the maintenance pool" — and the reason is that the state flip
    /// and the enqueue must be ONE transaction. Split across two connections, a
    /// crash between them leaves either a plan in `applying` that no job will
    /// ever pick up (a 202 that never happens) or a job for a plan that was
    /// never flipped (which the handler refuses on condition 1, correctly, but
    /// noisily and after the fact).
    ///
    /// # Plain enqueue, NOT `enqueue_unique_pending`
    ///
    /// `PostgresJobQueue::enqueue_unique_pending` guards on `job_type` plus
    /// `state = 'pending'` and discriminates nothing about the payload, so a
    /// second plan's apply would be silently dropped while the first is queued.
    /// A privatization that reports 202 and never runs is the failure this
    /// function's shape refuses.
    ///
    /// # `max_retries` IS AN ATTEMPT BUDGET, NOT A COUNT OF RETRIES AFTER THE
    /// FIRST
    ///
    /// `JobRunner`'s worker loop evaluates `job.retry_count >= job.max_retries`
    /// BEFORE it calls `handler.handle`, and marks the job `failed` when it
    /// holds. So the row's invariant at first dequeue is
    /// `retry_count < max_retries`, and a row inserted with `(0, 0)` is failed
    /// without the handler ever running — a 202 that never happens, which is the
    /// failure this function's shape exists to refuse.
    ///
    /// `1` is therefore the value that means what `JobHandler::max_retries() =
    /// 0` means on these two handlers: exactly ONE attempt, no exponential
    /// ladder. Recovery from a partial apply is the stale-job reaper
    /// re-dispatching, which re-runs the full re-validation, not a retry into
    /// the same lock timeout. (`JobHandler::max_retries` is not consulted by the
    /// runner at all — the row's column is the only load-bearing number — which
    /// is why this one is spelled out here rather than inferred.)
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault. A `42501` here is migration 077's
    /// `jobs_app` policy refusing the connection, which is the answer for every
    /// role but the maintenance one.
    pub async fn enqueue_job_conn(
        conn: &mut PgConnection,
        job_type: &str,
        payload: &serde_json::Value,
    ) -> Result<Uuid, DbError> {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO public.jobs
                   (id, job_type, payload, state, retry_count, max_retries,
                    created_at, updated_at)
            VALUES (gen_random_uuid(), $1, $2, 'pending', 0, 1, now(), now())
            RETURNING id
            "#,
        )
        .bind(job_type)
        .bind(payload)
        .fetch_one(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// The entity ids of a plan's items in `state='applied'`.
    ///
    /// The seed set of the post-apply drift rescan, and the ONLY place in this
    /// module where a bare `Vec<Uuid>` of plan items leaves a function without
    /// an actor's viewer in sight. That is sound for exactly one reason and it
    /// is worth being explicit about: its single caller is a JOB HANDLER, which
    /// has no requesting principal to filter against, and the ids' only
    /// destinations are `privatization_plans.drift_ids`, the frozen item set of
    /// a follow-up plan, and `privatization_audit` — three `FORCE`-protected
    /// tables that are read back through a policy. They do not reach a response
    /// body. A request-path caller that wanted this list would need
    /// [`Self::load_plan_items_conn`] and the rendering pass instead.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn applied_entity_ids_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
    ) -> Result<Vec<Uuid>, DbError> {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT i.entity_id
              FROM public.privatization_plan_items i
             WHERE i.plan_id = $1 AND i.kind = 'claim' AND i.state = 'applied'
             ORDER BY i.entity_id
            "#,
        )
        .bind(plan_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Per-state item counts, for `GET /plans/:id`'s live progress block.
    ///
    /// Discharges the apply-time half of `F-PR18b-preview-schema-is-a-subset`:
    /// §6.5.7 gives that row "preview + live progress", and progress is the
    /// cursor plus this histogram. Counts only — the entity ids behind them are
    /// [`Self::load_plan_items_conn`]'s, and reach the wire only through
    /// [`Self::visible_previews`].
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn item_state_counts_conn(
        conn: &mut PgConnection,
        plan_id: Uuid,
    ) -> Result<BTreeMap<String, i64>, DbError> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            r#"
            SELECT i.state, count(*)
              FROM public.privatization_plan_items i
             WHERE i.plan_id = $1
             GROUP BY i.state
             ORDER BY i.state
            "#,
        )
        .bind(plan_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(rows.into_iter().collect())
    }

    /// Append one PLAN-level row to `privatization_audit`.
    ///
    /// The table is append-only by three independent controls (082's
    /// `privatization_audit_no_mutate` trigger, its `REVOKE UPDATE, DELETE`, and
    /// the absence of an UPDATE or DELETE policy), so there is nothing here that
    /// can rewrite history — only add to it.
    ///
    /// FINAL-PLAN §6.5.5: "Every refusal writes `privatization_audit(action=
    /// 'plan.abort')` and sets `state='failed'`." Both halves are the caller's
    /// to sequence; this is the first half's primitive.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn record_plan_audit_conn(
        conn: &mut PgConnection,
        entry: PlanAuditEntry<'_>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO public.privatization_audit
                   (plan_id, actor_agent_id, action, kind, entity_id,
                    plan_digest, correlation_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(entry.plan_id)
        .bind(entry.actor_agent_id)
        .bind(entry.action)
        .bind(entry.kind)
        .bind(entry.entity_id)
        .bind(entry.plan_digest)
        .bind(entry.correlation_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Append one audit row PER ITEM in a batch, set-based.
    ///
    /// The before/after tenancy pair is read from `privatization_plan_items` and
    /// `claims` in the SAME statement, so the audit row describes the rows as
    /// the database holds them rather than as Rust believed them to be. A
    /// row-at-a-time loop over 50 items would also be 50 round trips inside a
    /// transaction holding the global privatization lock.
    ///
    /// Which projection, and therefore which side of the tenancy write this must
    /// be called on, is [`ItemAuditDirection`]'s doc.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn record_item_audit_conn(
        conn: &mut PgConnection,
        batch: ItemAuditBatch<'_>,
    ) -> Result<u64, DbError> {
        if batch.entity_ids.is_empty() {
            return Ok(0);
        }
        // Both fragments are compile-time literals chosen by an enum; nothing a
        // caller supplies reaches the statement text.
        let (pair, stamp) = match batch.direction {
            ItemAuditDirection::Apply => (
                "i.before_visibility, i.before_owner_group_id, c.visibility, c.owner_group_id",
                "",
            ),
            ItemAuditDirection::Revert => (
                "c.visibility, c.owner_group_id, i.before_visibility, i.before_owner_group_id",
                "AND c.visibility = 'group' AND c.owner_group_id = $6",
            ),
        };
        let sql = format!(
            "INSERT INTO public.privatization_audit
                    (plan_id, actor_agent_id, action, kind, entity_id,
                     before_visibility, before_owner_group_id,
                     after_visibility, after_owner_group_id, correlation_id)
             SELECT $1, $2, $3, 'claim', i.entity_id, {pair}, $5
               FROM public.privatization_plan_items i
               JOIN public.claims c ON c.id = i.entity_id
              WHERE i.plan_id = $1 AND i.kind = 'claim' AND i.entity_id = ANY($4) {stamp}"
        );
        let mut query = sqlx::query(&sql)
            .bind(batch.plan_id)
            .bind(batch.actor_agent_id)
            .bind(batch.action)
            .bind(batch.entity_ids)
            .bind(batch.correlation_id);
        if batch.direction == ItemAuditDirection::Revert {
            query = query.bind(batch.target_group_id);
        }
        query
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected())
            .map_err(|source| DbError::QueryFailed { source })
    }

    /// One page of `privatization_audit`, through migration 083's read policy.
    ///
    /// # This must be given a STAMPED APP connection
    ///
    /// `privatization_audit` has no `visibility` column; its tenancy IS 083's
    /// `privatization_audit_read` policy, which admits plan-level rows to any
    /// instance admin and entity-level rows only where the caller administers
    /// the plan's target group. That resolves through a sub-select over
    /// `privatization_plans`, which migration 087's own SELECT policy filters —
    /// so the scoping is two policies deep and BOTH are properties of the
    /// connection. On the maintenance connection `epigraph_bypass()` is true and
    /// this becomes the instance-wide oracle §6.5.8 argues against.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn load_audit_conn(
        conn: &mut PgConnection,
        query: AuditQuery,
    ) -> Result<Vec<AuditRow>, DbError> {
        sqlx::query_as::<_, AuditRow>(
            r#"
            SELECT a.id, a.plan_id, a.actor_agent_id, a.action, a.kind, a.entity_id,
                   a.before_visibility, a.after_visibility, a.correlation_id, a.created_at
              FROM public.privatization_audit a
             WHERE ($1::uuid IS NULL OR a.plan_id = $1)
               AND ($2::uuid IS NULL OR a.entity_id = $2)
               AND ($3::timestamptz IS NULL OR a.created_at >= $3)
             ORDER BY a.created_at DESC, a.id DESC
             LIMIT $4
            "#,
        )
        .bind(query.plan_id)
        .bind(query.entity_id)
        .bind(query.since)
        .bind(query.limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
    }

    /// Persist the post-apply drift rescan as a follow-up plan in `previewed`.
    ///
    /// FINAL-PLAN §6.5.5's sec-F9 fix. The rescan's answer to what the frozen
    /// selection does not cover is a NEW plan against the same target group, in
    /// `previewed`, so an operator reviews and applies it through the ordinary
    /// four-eyes surface rather than the handler privatizing rows nobody
    /// selected.
    ///
    /// # It lives in this crate and not in the handler, on purpose
    ///
    /// Building the follow-up needs [`UnfilteredSelection::from_selected`],
    /// which is a test-only escape hatch fenced off from the request path by
    /// `locked_decisions.rs::d4_the_request_path_reaches_privatization_only_through_the_composed_entry_point`.
    /// Doing it here keeps the hatch inside the module that owns it instead of
    /// spreading it to a crate that lint does not scan.
    ///
    /// Migration 081's plan guard fires on the INSERT, so a target group that
    /// has since lost its admin plurality refuses the follow-up rather than
    /// silently creating one nobody can approve.
    ///
    /// # `authors_losing_count` IS COMPUTED, NOT ASSERTED
    ///
    /// That column is not bookkeeping. Three independent gates key on
    /// `authors_losing_count > 0` — `routes/privatization.rs::apply_plan`'s
    /// second-approver `428`, the handler's re-validation condition 2, and
    /// condition 5's `acknowledge_author_loss` requirement — and `mode` is
    /// inherited from the source plan. A follow-up written with a hardcoded zero
    /// would route a plan that costs authors access to their own claims through
    /// the single-approver path, which is the one shape the four-eyes rule
    /// exists to refuse. So this runs the same
    /// [`Self::authors_losing_own_claims`] pass `create_plan` runs, under the
    /// bypass viewer the rescan already holds, and a fault there refuses the
    /// follow-up rather than downgrading it.
    ///
    /// The `selector` describes the DRIFT SET rather than an empty seed list,
    /// because the follow-up's review surface is the four-eyes surface: an
    /// operator asked to approve it must be able to see what it covers.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault, including the guard's `RAISE`.
    pub async fn create_followup_drift_plan_conn(
        conn: &mut PgConnection,
        viewer: &Viewer,
        source: &PlanRow,
        drift: &[SelectedClaim],
        created_by: Uuid,
    ) -> Result<Option<Uuid>, DbError> {
        if drift.is_empty() {
            return Ok(None);
        }
        let selection = UnfilteredSelection::from_selected(drift.to_vec());
        let digest = selection.digest();
        let authors_losing = selection
            .authors_losing_own_claims(&mut *conn, viewer, source.target_group_id)
            .await?;
        let selector = serde_json::json!({
            "seeds": { "ids": { "claims": selection.ids() } },
            "origin": { "drift_rescan_of": source.id },
        });
        let (plan_id, _) = Self::create_previewed_plan(
            &mut *conn,
            NewPlan {
                mode: &source.mode,
                target_group_id: source.target_group_id,
                selector: &selector,
                on_conflict: &source.on_conflict,
                pad_to: source.pad_to,
                created_by,
                plan_digest: &digest,
                item_count: i32::try_from(selection.item_count()).unwrap_or(i32::MAX),
                authors_losing_count: i32::try_from(authors_losing).unwrap_or(i32::MAX),
            },
        )
        .await?;
        selection.freeze_into(&mut *conn, plan_id).await?;
        Ok(Some(plan_id))
    }

    /// The post-apply restatement-tier drift rescan (sec F9).
    ///
    /// One hop out from the applied set along the RESTATEMENT tier only, plus
    /// the mandatory content-lineage hull over the result, minus everything the
    /// plan already covers. What is left is a claim that restates private
    /// content and is not itself private.
    ///
    /// # Depth 1, restatement tier, and nothing wider
    ///
    /// §6.5.5 says "re-run the closure at depth 1 over the applied set,
    /// restricted to the restatement tier, plus `epigraph_content_lineage_hull`
    /// over the applied ids". A wider rescan would report every claim that
    /// merely CITES a private one, which is not a leak and would make the
    /// follow-up plan an ever-growing privatization of the corpus.
    ///
    /// # It goes through the repo hull, not the SQL function
    ///
    /// `F-PR18a-hull-sibling-arm-is-one-hop` is closed at THIS layer — the
    /// re-seeding loop in [`Self::select_content_lineage_hull`] — and not in the
    /// DDL, so a caller that reached `epigraph_content_lineage_hull` directly
    /// would re-open it. This calls the repo function.
    ///
    /// # Authority
    ///
    /// `viewer` is the BYPASS viewer, for the reason every selection function
    /// takes one: a rescan narrowed to what someone can see reports less drift
    /// than exists. There is NO ACTOR VIEWER on this path at all — a job handler
    /// has no requesting principal — and the answer to
    /// `F-PR18a-selection-functions-are-invoker-bound-only-on-a-stamped-connection`'s
    /// second question is therefore that the returned ids are NOT re-filtered
    /// before leaving this function. They do not leave the process: their only
    /// destinations are `privatization_plans.drift_ids`, the frozen item set of
    /// the follow-up plan, and `privatization_audit`. All three are
    /// `FORCE`-protected tables read back through a policy.
    ///
    /// # Errors
    ///
    /// [`SelectionRefusal`] for a bad request; [`DbError`] for a query fault.
    pub async fn restatement_drift_conn(
        conn: &mut PgConnection,
        viewer: &Viewer,
        applied: &[Uuid],
        node_cap: i32,
    ) -> Result<Vec<SelectedClaim>, SelectionError> {
        if applied.is_empty() {
            return Ok(Vec::new());
        }
        let edge_types: Vec<String> = RESTATEMENT_EDGE_TYPES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let closure = Self::select_closure(
            conn,
            viewer,
            ClosureRequest {
                seeds: applied,
                edge_types: &edge_types,
                direction: ClosureDirection::Both,
                max_depth: 1,
                node_cap,
            },
        )
        .await?;
        let hulled = Self::select_content_lineage_hull(conn, viewer, &closure, node_cap).await?;

        let already: std::collections::BTreeSet<Uuid> = applied.iter().copied().collect();
        let candidates: Vec<Uuid> = hulled
            .iter()
            .map(|c| c.claim_id)
            .filter(|id| !already.contains(id))
            .collect();
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        // STILL PUBLIC is the whole question. A candidate that is already
        // `group` is not drift — it may be private for an unrelated reason, and
        // re-privatizing it into this plan's target group would be a seizure the
        // operator did not ask for.
        let sql = viewer.splice(
            r#"
            SELECT c.id
              FROM public.claims c
             WHERE c.id = ANY($1)
               AND c.visibility = 'public'
               /* {VISIBILITY:c} */
             ORDER BY c.id
            "#,
            2,
        );
        let mut query = sqlx::query_scalar::<_, Uuid>(&sql).bind(&candidates);
        if let Some(groups) = viewer.group_bind() {
            query = query.bind(groups);
        }
        let still_public: std::collections::BTreeSet<Uuid> = query
            .fetch_all(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?
            .into_iter()
            .collect();

        Ok(hulled
            .into_iter()
            .filter(|c| still_public.contains(&c.claim_id))
            .collect())
    }

    // =====================================================================
    // The frozen-set digest.
    // =====================================================================

    /// BLAKE3 over the sorted `(kind, entity_id)` pairs of a selection.
    ///
    /// FINAL-PLAN §6.5.1 makes the selection a PERSISTED object rather than a
    /// stateless request: an apply re-states this digest and is refused if the
    /// selection has moved underneath it. The sort is what makes the digest a
    /// property of the SET and not of the order a particular query returned it
    /// in, so two previews of an unchanged corpus agree.
    ///
    /// The separator bytes matter: without them `("claim", "ab") ("c", …)` and
    /// `("claimc", …)` would hash identically.
    ///
    /// # It covers the SELECTION SET and nothing else
    ///
    /// Not `target_group_id`, not `mode`, not `on_conflict`, not `pad_to`. Two
    /// plans over the same entities that would move them into different groups,
    /// or one `restrict` and one `seal`, hash identically. So this value is a
    /// staleness check on the selection — "has the corpus moved underneath the
    /// plan?" — and it is **not a plan identity**. An approval must bind to
    /// `privatization_plans.id`; a slice that binds an approval to this digest
    /// would let an approval of one plan authorise a different one.
    #[must_use]
    pub fn plan_digest(items: &[(String, Uuid)]) -> [u8; 32] {
        let mut sorted: Vec<&(String, Uuid)> = items.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        sorted.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

        let mut hasher = blake3::Hasher::new();
        for (kind, id) in sorted {
            hasher.update(kind.as_bytes());
            hasher.update(&[0x1f]);
            hasher.update(id.as_bytes());
            hasher.update(&[0x1e]);
        }
        *hasher.finalize().as_bytes()
    }
}

// =========================================================================
// THE TYPE-LEVEL SPLIT.
// =========================================================================

/// The selection pass's output, in a shape a request handler cannot read ids
/// out of.
///
/// This closes the obligation the module doc used to owe: `SelectedClaim` and
/// `ItemPreview` both carry a bare `Uuid`, so nothing stopped a handler that had
/// run the UNFILTERED pass from serialising its ids. The field below is private,
/// there is no `Deref`, no `AsRef`, no `ids()`, and no `IntoIterator`. Every
/// method that can produce an entity id either takes the ACTOR's `Viewer` or
/// writes into a `FORCE`-protected table and returns a count.
///
/// [`Self::into_selected`] and [`Self::from_selected`] are the TWO unguarded
/// exits and exist for tests. The request path is held off both by
/// `crates/epigraph-db/tests/locked_decisions.rs::d4_the_request_path_reaches_privatization_only_through_the_composed_entry_point`,
/// a source lint, because the tests that legitimately need them live in a
/// different crate and so cannot be served by Rust visibility. An earlier
/// revision of this doc named a file that has never existed
/// (`crates/epigraph-api/tests/privatization_route_surface.rs`) while the
/// module-level doc named the real one, so a reader auditing whether the escape
/// hatches are still fenced would have found nothing and could reasonably have
/// concluded the fence was dropped.
#[derive(Debug, Clone)]
pub struct UnfilteredSelection {
    items: Vec<SelectedClaim>,
}

impl UnfilteredSelection {
    /// How many entities the plan would privatize.
    ///
    /// This is a COUNT and is NOT re-filtered against the actor — re-filtering
    /// it would report a plan smaller than the one that will be applied.
    #[must_use]
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Whether the selection is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// `depth -> count`, the preview's `counts.by_depth`.
    #[must_use]
    pub fn by_depth(&self) -> BTreeMap<i32, i64> {
        let mut out = BTreeMap::new();
        for item in &self.items {
            *out.entry(item.depth).or_insert(0) += 1;
        }
        out
    }

    /// How many items are seeds (`depth == 0`).
    #[must_use]
    pub fn seed_count(&self) -> usize {
        self.items.iter().filter(|i| i.depth == 0).count()
    }

    /// How many items the mandatory hull contributed.
    #[must_use]
    pub fn hull_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.via.starts_with("hull:"))
            .count()
    }

    /// BLAKE3 over the frozen `(kind, entity_id)` set.
    ///
    /// Every item this module selects is a `claim`; the kind is spelled out so
    /// the digest is stable when a later slice adds `evidence` items.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let pairs: Vec<(String, Uuid)> = self
            .items
            .iter()
            .map(|i| ("claim".to_string(), i.claim_id))
            .collect();
        PrivatizationRepository::plan_digest(&pairs)
    }

    /// Boundary-edge counts by relationship, unfiltered.
    ///
    /// A COUNT, so it is safe to show to any authorized caller. See
    /// [`PrivatizationRepository::boundary_edge_counts`] for what it excludes —
    /// the honest name for this subtotal is `boundary_edges.claim_to_claim`.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn boundary_edge_counts(
        &self,
        conn: &mut PgConnection,
        viewer: &Viewer,
    ) -> Result<Vec<BoundaryEdgeCount>, DbError> {
        PrivatizationRepository::boundary_edge_counts(conn, viewer, &self.ids()).await
    }

    /// How many distinct authors would lose access to their own claims.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn authors_losing_own_claims(
        &self,
        conn: &mut PgConnection,
        viewer: &Viewer,
        target_group_id: Uuid,
    ) -> Result<i64, DbError> {
        PrivatizationRepository::authors_losing_own_claims(
            conn,
            viewer,
            &self.ids(),
            target_group_id,
        )
        .await
    }

    /// Which NOT-traversed relationships would have extended the selection.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn omitted_edge_types(
        &self,
        conn: &mut PgConnection,
        viewer: &Viewer,
        traversed: &[String],
    ) -> Result<Vec<OmittedEdgeTypeWarning>, DbError> {
        PrivatizationRepository::omitted_edge_types(conn, viewer, &self.ids(), traversed).await
    }

    /// The `sample` block: items the ACTOR can read, stratified by depth.
    ///
    /// `viewer` is the actor's own and a bypass viewer is refused, by
    /// [`PrivatizationRepository::visible_previews`].
    ///
    /// # The stratification happens BEFORE the rendering pass, and that is a
    /// bound rather than a bias
    ///
    /// A selection may hold up to [`MAX_NODE_CAP`] items and each preview
    /// carries [`PREVIEW_CHARS`] of content, so rendering the whole set to pick
    /// twenty-five of it would move a quarter of a gigabyte to discard almost
    /// all of it. Instead a depth-stratified candidate window of
    /// [`SAMPLE_CANDIDATE_WINDOW`] ids is drawn first, round-robin across depth
    /// bands so no band is starved, and only that window is rendered.
    ///
    /// The consequence, stated rather than hidden: the sample can come back
    /// SHORTER than `sample_size` even when the actor could read more of the
    /// selection, because the window may be mostly invisible to them. That is
    /// the right direction — a short sample understates, and the decision-
    /// relevant figures are the counts, which are complete. It is NOT the
    /// number the preview reports as `not_visible_to_actor`; that one is
    /// [`Self::visible_count`], measured over the WHOLE selection.
    ///
    /// # Errors
    ///
    /// [`SelectionRefusal::BypassViewerInRenderingPass`] for a bypass viewer;
    /// [`DbError`] for a query fault.
    pub async fn render_previews(
        &self,
        conn: &mut PgConnection,
        viewer: &Viewer,
        sample_size: usize,
    ) -> Result<Vec<ItemPreview>, SelectionError> {
        if sample_size == 0 {
            return Ok(Vec::new());
        }
        let window = self.stratified_window(SAMPLE_CANDIDATE_WINDOW);
        let mut rendered = PrivatizationRepository::visible_previews(conn, viewer, &window).await?;
        rendered.truncate(sample_size);
        Ok(rendered)
    }

    /// The `boundary_edges.sample` block: boundary edge ids the ACTOR can read.
    ///
    /// # Errors
    ///
    /// [`SelectionRefusal::BypassViewerInRenderingPass`] for a bypass viewer;
    /// [`DbError`] for a query fault.
    pub async fn render_boundary_edges(
        &self,
        conn: &mut PgConnection,
        viewer: &Viewer,
        limit: i64,
    ) -> Result<Vec<Uuid>, SelectionError> {
        PrivatizationRepository::visible_boundary_edges(conn, viewer, &self.ids(), limit).await
    }

    /// How many selected items the ACTOR can read.
    ///
    /// The preview reports `item_count() - visible_count()` as
    /// `not_visible_to_actor`: a number, never a list. This is the production
    /// half of a subtraction that used to exist only in a test body.
    ///
    /// # Errors
    ///
    /// [`SelectionRefusal::BypassViewerInRenderingPass`] for a bypass viewer;
    /// [`DbError`] for a query fault.
    pub async fn visible_count(
        &self,
        conn: &mut PgConnection,
        viewer: &Viewer,
    ) -> Result<i64, SelectionError> {
        PrivatizationRepository::count_visible(conn, viewer, &self.ids()).await
    }

    /// Freeze the selection into `privatization_plan_items`.
    ///
    /// Returns the number of item rows written and NO ids: the entity ids go
    /// from this process into a `FORCE`-protected table and come back out only
    /// through [`PrivatizationRepository::load_plan_items_conn`], which requires a
    /// connection migration 087's policy admits.
    ///
    /// # Which connection
    ///
    /// The MAINTENANCE one. 087's INSERT arm is `epigraph_bypass()` alone and
    /// 080 REVOKEs INSERT from `epigraph_app`.
    ///
    /// # The `before_*` columns are read here and not carried from selection
    ///
    /// `before_visibility`, `before_owner_group_id` and `before_had_embedding`
    /// are what a revert restores, so they are read from `claims` in the SAME
    /// statement that writes the item — not from a value the selection pass
    /// captured earlier. A round trip through Rust would widen the window in
    /// which a concurrent write makes the recorded "before" wrong, and a wrong
    /// `before` is an unrevertable privatization.
    ///
    /// The join to `claims` is an INNER one, so an id that no longer names a
    /// live claim is silently absent from the frozen set. That is why the return
    /// value is the ROW COUNT rather than [`Self::item_count`]: the caller
    /// stores what was actually frozen.
    ///
    /// # Errors
    ///
    /// [`DbError`] for a query fault.
    pub async fn freeze_into(
        &self,
        conn: &mut PgConnection,
        plan_id: Uuid,
    ) -> Result<u64, DbError> {
        if self.items.is_empty() {
            return Ok(0);
        }
        let ids: Vec<Uuid> = self.items.iter().map(|i| i.claim_id).collect();
        let depths: Vec<i32> = self.items.iter().map(|i| i.depth).collect();
        let vias: Vec<String> = self.items.iter().map(|i| i.via.clone()).collect();

        let result = sqlx::query(
            r#"
            INSERT INTO public.privatization_plan_items
                   (plan_id, kind, entity_id, depth, via,
                    before_visibility, before_owner_group_id, before_had_embedding)
            SELECT $1, 'claim', c.id, s.depth, s.via,
                   c.visibility, c.owner_group_id, (c.embedding IS NOT NULL)
              FROM unnest($2::uuid[], $3::int[], $4::text[]) AS s(entity_id, depth, via)
              JOIN public.claims c ON c.id = s.entity_id
            ON CONFLICT (plan_id, kind, entity_id) DO NOTHING
            "#,
        )
        .bind(plan_id)
        .bind(&ids)
        .bind(&depths)
        .bind(&vias)
        .execute(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        Ok(result.rows_affected())
    }

    /// The raw selection. **Tests only** — see the type's doc.
    #[must_use]
    pub fn into_selected(self) -> Vec<SelectedClaim> {
        self.items
    }

    /// Build one from an already-computed selection. **Tests only.**
    #[must_use]
    pub fn from_selected(items: Vec<SelectedClaim>) -> Self {
        Self { items }
    }

    /// Private: the id vector the repo primitives take.
    fn ids(&self) -> Vec<Uuid> {
        self.items.iter().map(|i| i.claim_id).collect()
    }

    /// Private: up to `window` ids, drawn round-robin across depth bands.
    fn stratified_window(&self, window: usize) -> Vec<Uuid> {
        if self.items.len() <= window {
            return self.ids();
        }
        let mut bands: BTreeMap<i32, Vec<Uuid>> = BTreeMap::new();
        for item in &self.items {
            bands.entry(item.depth).or_default().push(item.claim_id);
        }
        let mut out = Vec::with_capacity(window);
        let mut round = 0usize;
        while out.len() < window {
            let mut contributed = false;
            for ids in bands.values() {
                if let Some(id) = ids.get(round) {
                    out.push(*id);
                    contributed = true;
                    if out.len() == window {
                        break;
                    }
                }
            }
            if !contributed {
                break;
            }
            round += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_edge_types_are_classified_case_insensitively() {
        for name in STRUCTURAL_EDGE_TYPES {
            assert_eq!(classify_edge_type(name), EdgeTypeTier::Structural);
            assert_eq!(
                classify_edge_type(&name.to_ascii_uppercase()),
                EdgeTypeTier::Structural,
                "migration 011 documents both spellings in live data; a tier check \
                 that matched one would let the other through"
            );
        }
    }

    #[test]
    fn restatement_types_default_on_and_everything_else_is_epistemic() {
        assert_eq!(
            classify_edge_type("DERIVED_FROM"),
            EdgeTypeTier::Restatement
        );
        assert_eq!(
            classify_edge_type("decomposes_to"),
            EdgeTypeTier::Restatement
        );
        assert_eq!(classify_edge_type("supports"), EdgeTypeTier::Epistemic);
        assert_eq!(classify_edge_type("contradicts"), EdgeTypeTier::Epistemic);
    }

    #[test]
    fn the_digest_is_a_property_of_the_set_not_of_the_order() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let forwards = vec![("claim".to_string(), a), ("claim".to_string(), b)];
        let backwards = vec![("claim".to_string(), b), ("claim".to_string(), a)];
        assert_eq!(
            PrivatizationRepository::plan_digest(&forwards),
            PrivatizationRepository::plan_digest(&backwards)
        );
    }

    #[test]
    fn the_digest_separates_kind_from_id() {
        // Without the separator bytes these two distinct sets would collide.
        let id = Uuid::from_u128(1);
        let as_claim = vec![("claim".to_string(), id)];
        let as_evidence = vec![("evidence".to_string(), id)];
        assert_ne!(
            PrivatizationRepository::plan_digest(&as_claim),
            PrivatizationRepository::plan_digest(&as_evidence)
        );
    }

    #[test]
    fn the_digest_changes_when_the_set_changes() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let one = vec![("claim".to_string(), a)];
        let two = vec![("claim".to_string(), a), ("claim".to_string(), b)];
        assert_ne!(
            PrivatizationRepository::plan_digest(&one),
            PrivatizationRepository::plan_digest(&two),
            "an apply must be refused when the selection has grown underneath it"
        );
    }
}
