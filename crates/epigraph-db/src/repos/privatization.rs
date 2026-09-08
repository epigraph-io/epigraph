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
//! # What this module deliberately does not do
//!
//! It does not INSERT `privatization_plans` or `privatization_plan_items`, and
//! it does not read them. Migration 080 creates both with `ENABLE` + `FORCE`
//! row-level security and **no policy**, which denies every command to every
//! role that is not `BYPASSRLS` — including `epigraph_maintenance`. Persisting
//! and reading a plan therefore requires a policy, a policy requires a
//! migration, and no migration number is assigned to this slice. The functions
//! here are the whole computation a persisted plan would store; wiring them to
//! a table is the next slice's, once a number is allocated.
//!
//! Nothing here mutates `claims.visibility`, `claims.owner_group_id`, or any
//! other tenancy column. Applying a plan is a separate, later surface.

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

/// The request shape for a closure traversal.
///
/// `max_depth` and `node_cap` are the CALLER's bounds and are checked only for
/// positivity here. FINAL-PLAN §3.1 additionally names two system ceilings —
/// `node_cap` at most 250,000, `max_depth` at most 6, exceeding either being a
/// 400 — which belong to the request-validation layer that shapes an HTTP body
/// into this struct. That layer does not exist yet, so the ceilings are owed,
/// not enforced. They answer a different question from
/// [`SelectionRefusal::NodeCapExceeded`], which is about the SELECTION
/// exceeding the cap the caller asked for.
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

/// The largest boundary-edge SAMPLE
/// [`PrivatizationRepository::visible_boundary_edges`] will return.
///
/// A sample exists so the operator can inspect a few straddling edges; the
/// decision-relevant number is the count. Without a ceiling a caller could ask
/// for the whole boundary and turn the sample into the survey.
pub const MAX_BOUNDARY_EDGE_SAMPLE: i64 = 1000;

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
