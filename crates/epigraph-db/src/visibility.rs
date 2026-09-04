//! Read authority for one principal, for one request.
//!
//! This module defines [`Viewer`], the value every tenancy-aware read will take
//! (PR-06 threads it through the repo layer; PR-07 threads it through the HTTP
//! layer). PR-03 lands the type, its two shapes, and the one constructor that a
//! request path can reach — [`Viewer::resolve`].
//!
//! # Invariants, enforced by construction
//!
//! * **There is no anonymous shape.** A caller without an `agents.id` cannot
//!   build a `Viewer` at all; the 401 happens in the extractor
//!   (`epigraph_api::middleware::bearer::ViewerExtractor`). A third
//!   "matches nothing" shape was considered and rejected: it is invisible to a
//!   test strategy written as *"assert a stranger CANNOT read"*, so an
//!   over-restricting viewer would pass every adversarial test while producing
//!   silent, permanent empty result sets.
//! * **No `Default`, no `From<Option<Uuid>>`, no `From<&AuthContext>`, no
//!   zero-argument `unrestricted()`.** Every one of those is a way to
//!   materialise read authority out of nothing at a call site that looks
//!   innocent. `crates/epigraph-db/tests/no_anonymous_viewer.rs` fails the
//!   build if any of them reappears in this file.
//! * **The only unrestricted shape requires a [`MaintenanceLease`]**, which
//!   only the maintenance-pool accessor can mint (`ScopedPool`, PR-04). This is
//!   not ceremony: once RLS is FORCEd, a `Bypass` viewer emits no SQL predicate
//!   but the database policy still filters, so `Viewer::system(..)` on an
//!   ordinary `epigraph_app` connection returns **zero** rows, not all rows.
//!   The lease makes "unrestricted viewer" and "maintenance connection"
//!   inseparable at the type level.
//!
//! # The splice mechanism (PR-06)
//!
//! [`Viewer::predicate_fragment`] landed in PR-04, alongside the tenancy columns
//! it references (`claims.visibility`, `claims.owner_group_id`, migration 062).
//! It is a *template*: `{alias}` and `$V` are placeholders, and PR-04 shipped no
//! way to fill them in. PR-06 adds that way, and makes it the only one.
//!
//! A repo-layer read now writes its marker into the SQL text itself —
//!
//! ```sql
//! WHERE c.is_current = true /* {VISIBILITY:c} */
//! ```
//!
//! — and wraps the literal in [`Viewer::splice`], which replaces every marker
//! with [`Viewer::render_predicate`]'s output at a caller-chosen bind index.
//! Three properties make this safer than hand-substitution at each site:
//!
//! * `splice` **panics** when the literal contains no marker. A read that was
//!   converted to take a `&Viewer` but never had its marker inserted is exactly
//!   the fail-open this PR exists to prevent, and a required parameter that is
//!   silently ignored is invisible in review. The panic is a programming-error
//!   panic on a `&'static str` the developer just wrote, not a runtime path.
//! * Every marker in one statement resolves to the **same** bind index, asserted
//!   inside `splice`. Two CTEs over `claims` in one query (see
//!   `ClaimRepository::search_hybrid_scoped_since`) must both filter, and both
//!   read the same `$V`.
//! * [`VISIBILITY_MARKER_PREFIX`] and [`EDGE_VISIBILITY_MARKER_PREFIX`] are the
//!   only two spellings of the marker, shared with
//!   `crates/epigraph-db/tests/visibility_lint.rs`, so the lint and the repo
//!   layer cannot drift apart.
//!
//! # Two markers, because an alias is a substitution and not a dispatch key
//! (PR-13)
//!
//! `splice` reads the alias out of the marker and hands it to
//! [`Viewer::render_predicate`] as *text*. Nothing in that chain knows which
//! TABLE an alias names, and the aliases genuinely collide:
//! `repos/structural.rs::degrees` writes `FROM edges e`, while
//! `repos/evidence.rs::provided_for_claim_as_of` writes
//! `FROM evidence e JOIN edges ed` — `e` is `edges` in one statement and
//! `evidence` in the other. So the `edges` fragment cannot be selected by
//! alias; it needs its own marker:
//!
//! ```sql
//! WHERE e.valid_to IS NULL /* {EDGE_VISIBILITY:e} */
//! ```
//!
//! Both spellings resolve to the SAME bind index (one `$V` per statement), both
//! are accepted by `splice`'s missing-marker assertion, and
//! `visibility_lint.rs::every_spliced_statement_carries_the_canonical_marker_spelling`
//! accepts either — but still rejects a `.splice(` body carrying neither.
//! The two prefixes are disjoint strings (`/* {EDGE_VISIBILITY:` does not
//! contain `/* {VISIBILITY:`), so the two substitution passes inside `splice`
//! are order-independent.
//!
//! `sqlx::query!` cannot be spliced — the macro needs a compile-time literal of
//! fixed arity, and the two shapes differ in bind count. The four macro read
//! sites in `repos/claim.rs` instead carry the static three-bind form
//! `AND ($N::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($M::uuid[]))`,
//! bound from [`Viewer::bypass_bind`] and [`Viewer::group_bind`]. That is the
//! form `AgentRepository::get_public_profile` already uses (PR-04), and
//! `visibility_lint.rs` accepts both spellings.
//!
//! # What is deliberately NOT here yet
//!
//! Nothing on the fragment side. PR-13 landed
//! [`Viewer::edge_predicate_fragment`] together with migration 072, which
//! creates the `edges.co_owner_group_id` it names — the ordering this note used
//! to enforce, because a fragment naming a column that does not exist is
//! compile-time-clean and runtime-fatal.
//!
//! What remains open is *coverage*, not capability: the never-filtered `edges`
//! traversals in `repos/graph_view.rs` (`expand_cluster_nodes`,
//! `neighborhood_*`, `compound_neighbors`), `repos/claim.rs`'s
//! `rag_hybrid_context.edge_count` and — the strongest of them, because it
//! projects `e.source_id`, `e.target_id` and `e.relationship` rather than a
//! scalar — `repos/claim.rs::semantic_graph_neighbors` still join `edges` with
//! no predicate at all. They are open finding `F-edges-unfiltered` in
//! `docs/tenancy/progress.json`, re-scoped there rather than left as a comment
//! nobody owns. That list is bounded to `crates/epigraph-db`; the MCP tool
//! layer has its own unfiltered `edges` traversals (`epigraph-mcp/src/tools/
//! recall.rs` spends its viewer on `claims` only) and is recorded separately.
//!
//! PR-13 converted the reads that ALREADY carried a predicate and did not ADD
//! one anywhere, because a never-filtered statement needs its own
//! JOIN-vs-WHERE placement reasoning — in a `LEFT JOIN ... ON` used for
//! suppression, adding a filter is itself the fail-open — rather than a
//! fragment swap.

use crate::errors::DbError;
use crate::repos::GroupMembershipRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// The one spelling of the in-SQL visibility marker.
///
/// A repo-layer read writes `/* {VISIBILITY:<alias>} */` into its SQL text and
/// [`Viewer::splice`] replaces it. `crates/epigraph-db/tests/visibility_lint.rs`
/// matches on this same constant, so the lint and the repo layer cannot drift
/// to two different spellings of "this query is filtered".
pub const VISIBILITY_MARKER_PREFIX: &str = "/* {VISIBILITY:";

/// The `edges` spelling of the in-SQL visibility marker (PR-13).
///
/// `/* {EDGE_VISIBILITY:<alias>} */` splices
/// [`Viewer::edge_predicate_fragment`] — the co-ownership INTERSECTION — rather
/// than [`Viewer::predicate_fragment`]. It exists because the marker's alias is
/// a text substitution, not a dispatch key: `e` names `edges` in
/// `repos/structural.rs` and `evidence` in `repos/evidence.rs`, so which
/// fragment a marker wants cannot be inferred from the alias. See the module
/// docs.
///
/// Deliberately NOT a substring of [`VISIBILITY_MARKER_PREFIX`] and deliberately
/// not containing it, so the two substitution passes cannot capture each
/// other's markers.
pub const EDGE_VISIBILITY_MARKER_PREFIX: &str = "/* {EDGE_VISIBILITY:";

/// The closing half of the marker, split out so the two halves are never
/// written as separate literals at a call site. Shared by both spellings.
const VISIBILITY_MARKER_SUFFIX: &str = "} */";

/// Read authority for one principal, for one request.
///
/// See the [module documentation](self) for the invariants this type enforces.
#[derive(Clone, Debug)]
pub struct Viewer {
    shape: ViewerShape,
}

/// The two — and only two — shapes a [`Viewer`] can take.
///
/// Private on purpose: adding a shape must be a change to this file, which is
/// the file `no_anonymous_viewer.rs` watches.
#[derive(Clone, Debug)]
enum ViewerShape {
    /// An authenticated `agents.id` plus its live group set.
    ///
    /// `group_ids` is the set of `group_memberships.group_id` rows for the
    /// principal with `revoked_at IS NULL`. Today it can legitimately be empty
    /// for a principal that has joined nothing, and an empty group set is a
    /// *correct* answer, not an error.
    ///
    /// Plan §4.3 requires that it ALWAYS contain the principal's personal
    /// group. As of PR-04 it does, for every principal minted through
    /// `epigraph-api`'s `oauth/token.rs`: `AgentRepository::ensure_personal_group`
    /// (shipped in PR-02, `repos/agent.rs`) writes the principal its own
    /// `kind = 'personal'` group plus a live `role = 'admin'` membership in it,
    /// and `resolve` reads that membership like any other. No special-casing is
    /// needed here, and none should be added: the union is a *provisioning*
    /// property, not a query property.
    ///
    /// The invariant is silent when it fails, which is why
    /// `no_anonymous_viewer.rs::resolve_unions_in_the_principals_personal_group`
    /// pins it: a principal provisioned without a personal group produces a
    /// `Scoped` viewer that reads only `visibility = 'public'` forever, and the
    /// symptom looks like "the corpus is empty for new users" rather than like a
    /// bug in `resolve`.
    ///
    /// An agent inserted straight into `agents` by a fixture or a CLI bin has no
    /// personal group and therefore no membership — that is a correct, empty
    /// `Scoped` viewer, not an error.
    ///
    /// `writable` is the subset whose role is `admin` or `writer`.
    Scoped {
        principal: Uuid,
        group_ids: Vec<Uuid>,
        writable: Vec<Uuid>,
    },
    /// UNRESTRICTED. Background jobs and CLI bins only, **on a maintenance
    /// connection**. Unconstructible without a [`MaintenanceLease`].
    Bypass { reason: SystemReason },
}

/// The closed set of legitimate reasons to hold an unrestricted [`Viewer`].
///
/// A `&'static str` reason would make the ratchet a grep over source text,
/// defeated by `concat!`, a `const REASON`, or a macro. A closed enum makes the
/// ratchet `SystemReason::ALL.len()`, makes "add a bypass" a visible enum diff
/// in review, and makes the exhaustiveness check a `match` the compiler
/// enforces.
///
/// `#[non_exhaustive]` prevents downstream crates from matching without a
/// wildcard arm, so adding a variant here is not a breaking change for them —
/// but it *is* a change that `viewer_ratchet.rs` (PR-04) will refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SystemReason {
    /// Backfilling `claims.embedding` for rows that have none.
    EmbeddingBackfill,
    /// Recomputing belief/truth aggregates across the corpus.
    BeliefRecomputation,
    /// The semantic-duplicate sweep.
    DedupSweep,
    /// Corpus-wide theme clustering.
    ThemeClustering,
    /// One-shot backfill of the tenancy columns themselves.
    TenancyBackfill,
    /// Selecting candidates for privatization. Selection must be unfiltered to
    /// be correct — a filtered selection would silently skip the rows it is
    /// supposed to find.
    PrivatizationSelection,
    /// Applying a privatization decision, on the maintenance pool.
    PrivatizationApply,
    /// Re-sealing content under a rotated group key epoch.
    PrivatizationReseal,
    /// The schema-contract test suite.
    SchemaContractTest,
    /// The RLS canary: a probe that asserts the policy is actually filtering.
    RlsCanaryProbe,
}

impl SystemReason {
    /// Every variant, in declaration order.
    ///
    /// Kept in sync with the enum by the exhaustive `match` in
    /// `crates/epigraph-db/tests/no_anonymous_viewer.rs`: adding a variant
    /// without extending `ALL` fails to compile there.
    pub const ALL: &'static [SystemReason] = &[
        SystemReason::EmbeddingBackfill,
        SystemReason::BeliefRecomputation,
        SystemReason::DedupSweep,
        SystemReason::ThemeClustering,
        SystemReason::TenancyBackfill,
        SystemReason::PrivatizationSelection,
        SystemReason::PrivatizationApply,
        SystemReason::PrivatizationReseal,
        SystemReason::SchemaContractTest,
        SystemReason::RlsCanaryProbe,
    ];

    /// A stable, lowercase label for logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SystemReason::EmbeddingBackfill => "embedding_backfill",
            SystemReason::BeliefRecomputation => "belief_recomputation",
            SystemReason::DedupSweep => "dedup_sweep",
            SystemReason::ThemeClustering => "theme_clustering",
            SystemReason::TenancyBackfill => "tenancy_backfill",
            SystemReason::PrivatizationSelection => "privatization_selection",
            SystemReason::PrivatizationApply => "privatization_apply",
            SystemReason::PrivatizationReseal => "privatization_reseal",
            SystemReason::SchemaContractTest => "schema_contract_test",
            SystemReason::RlsCanaryProbe => "rls_canary_probe",
        }
    }
}

/// Proof that the caller holds a maintenance-role connection.
///
/// Minted ONLY by `ScopedPool::unscoped_for_maintenance` (PR-04). Not `Clone`,
/// not `Copy`, and its single field is `pub(crate)`, so no code outside
/// `epigraph-db` can construct one — which is the whole mechanism behind
/// [`Viewer::system`].
pub struct MaintenanceLease(pub(crate) ());

impl MaintenanceLease {
    /// Mint a lease. Crate-private: [`crate::pool::ScopedPool::unscoped_for_maintenance`]
    /// is the only caller, and it mints one only after handing out a connection
    /// on the maintenance role.
    pub(crate) const fn new() -> Self {
        MaintenanceLease(())
    }
}

impl std::fmt::Debug for MaintenanceLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MaintenanceLease")
    }
}

impl Viewer {
    /// The ONLY constructor reachable from a request path.
    ///
    /// One round trip:
    ///
    /// ```sql
    /// SELECT group_id, role FROM group_memberships
    ///  WHERE agent_id = $1 AND revoked_at IS NULL
    /// ```
    ///
    /// served index-only by `idx_group_memberships_agent_live`
    /// (`migrations/060_group_tenancy_tables.sql:268`), whose in-file comment
    /// already names this as the hot path.
    ///
    /// The SQL itself lives in
    /// [`GroupMembershipRepository::list_live_for_agent`] — CLAUDE.md requires
    /// all SQL to live under `crates/epigraph-db/src/repos/`, and this function
    /// deliberately contains none.
    ///
    /// An empty membership set is not an error: it yields a `Scoped` viewer
    /// over zero groups, which can still read public rows.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the membership query fails.
    #[allow(clippy::missing_panics_doc)]
    pub async fn resolve(pool: &PgPool, principal: Uuid) -> Result<Self, DbError> {
        let memberships = GroupMembershipRepository::list_live_for_agent(pool, principal).await?;

        let mut group_ids: Vec<Uuid> = Vec::with_capacity(memberships.len());
        let mut writable: Vec<Uuid> = Vec::new();
        for (group_id, role) in memberships {
            // `admin` and `writer` are the two write-capable roles in
            // `group_memberships_role_check` (migration 060:245). `reader` is
            // the third and only other legal value; anything else is a row that
            // should not exist, and we treat it as read-only.
            if matches!(role.as_str(), "admin" | "writer") {
                writable.push(group_id);
            }
            group_ids.push(group_id);
        }
        group_ids.sort_unstable();
        group_ids.dedup();
        writable.sort_unstable();
        writable.dedup();

        Ok(Viewer {
            shape: ViewerShape::Scoped {
                principal,
                group_ids,
                writable,
            },
        })
    }

    /// Build the unrestricted viewer. Requires a [`MaintenanceLease`], which
    /// only a maintenance-role connection can produce.
    #[must_use]
    pub const fn system(_lease: &MaintenanceLease, reason: SystemReason) -> Self {
        Viewer {
            shape: ViewerShape::Bypass { reason },
        }
    }

    /// The authenticated principal, when there is one.
    ///
    /// `Some` for `Scoped`, `None` for `Bypass`. Deliberately **not** flattened
    /// into an `Option<Uuid>`-shaped convenience anywhere else: callers that
    /// care about the difference must `match`, and callers that do not should
    /// not be reaching for the principal at all.
    #[must_use]
    pub const fn principal(&self) -> Option<Uuid> {
        match self.shape {
            ViewerShape::Scoped { principal, .. } => Some(principal),
            ViewerShape::Bypass { .. } => None,
        }
    }

    /// The group set to bind as `$V` in a scoped query, sorted and deduplicated.
    ///
    /// `None` for `Bypass` — a bypass viewer emits no predicate, so it has no
    /// bind to supply.
    #[must_use]
    pub fn group_bind(&self) -> Option<&[Uuid]> {
        match &self.shape {
            ViewerShape::Scoped { group_ids, .. } => Some(group_ids),
            ViewerShape::Bypass { .. } => None,
        }
    }

    /// The subset of groups the principal may write to (role `admin` or
    /// `writer`). Empty for `Bypass` — write authority is not what a bypass
    /// grants, and a maintenance job that writes does so without a group.
    #[must_use]
    pub fn writable_groups(&self) -> &[Uuid] {
        match &self.shape {
            ViewerShape::Scoped { writable, .. } => writable,
            ViewerShape::Bypass { .. } => &[],
        }
    }

    /// The writable group set, in the same `Option` shape as [`Self::group_bind`].
    ///
    /// `None` for `Bypass`, so the two binds a scoped statement needs are read
    /// through symmetric accessors and a `Bypass` viewer cannot be mistaken for
    /// one with an empty writable set.
    #[must_use]
    pub fn writable_bind(&self) -> Option<&[Uuid]> {
        match &self.shape {
            ViewerShape::Scoped { writable, .. } => Some(writable),
            ViewerShape::Bypass { .. } => None,
        }
    }

    /// The SQL this viewer contributes to a tenancy-aware read.
    ///
    /// **Exactly two distinct strings**, one per shape. `{alias}` is substituted
    /// by the caller with the table alias the predicate applies to; `$V` is the
    /// single optional bind, supplied from [`Self::group_bind`] — from the
    /// *same* `Viewer` value, which is what makes qual/GUC coherence (plan §4.5)
    /// checkable rather than merely intended.
    ///
    /// Three properties are load-bearing and are pinned by unit tests:
    ///
    /// * **It is written inline.** No `epigraph_visible()` call: a SQL function
    ///   here would rest on an inlining assumption the planner is free to break,
    ///   and would add one more `SECURITY DEFINER`-adjacent surface to `REVOKE`.
    /// * **`visibility = 'public'` comes FIRST.** Cheap-first for the executor,
    ///   and it syntactically matches the leading disjunct of the RLS `USING`
    ///   clause in migration 077 — the property that lets RLS never reject a row
    ///   the app-emitted qual already returned.
    /// * **`Bypass` emits a single space, not an empty string.** The fragment is
    ///   spliced between other SQL tokens; an empty string would join them.
    ///
    /// The `edges` variant carrying the co-ownership INTERSECTION is
    /// [`Self::edge_predicate_fragment`] (PR-13). This fragment stays the one
    /// for every single-owner table, and is what
    /// `/* {VISIBILITY:<alias>} */` splices.
    #[must_use]
    pub const fn predicate_fragment(&self) -> &'static str {
        match self.shape {
            ViewerShape::Scoped { .. } => {
                " AND ({alias}.visibility = 'public' \
                   OR {alias}.owner_group_id = ANY($V::uuid[])) "
            }
            ViewerShape::Bypass { .. } => " ",
        }
    }

    /// [`Self::predicate_fragment`] for `edges`, which has TWO owning groups.
    ///
    /// `edges.co_owner_group_id` (migration 072) is the second owner of a
    /// cross-group edge — an edge whose endpoints are private to different
    /// groups G and H. It is `NULL` for every single-owner edge, which is the
    /// overwhelming majority, and the `IS NULL` disjunct short-circuits there.
    ///
    /// **The group clause is an INTERSECTION, not a union.** A co-owned edge is
    /// visible only to a principal in *both* G and H:
    ///
    /// ```sql
    /// AND (e.visibility = 'public'
    ///      OR (e.owner_group_id = ANY($V::uuid[])
    ///          AND (e.co_owner_group_id IS NULL
    ///               OR e.co_owner_group_id = ANY($V::uuid[]))))
    /// ```
    ///
    /// A union would defeat the point of the column: the edge exists precisely
    /// so that privatizing into two groups neither loses data nor discloses to
    /// one group an edge naming the other group's claim. Membership in G alone
    /// must not be enough.
    ///
    /// The same three properties [`Self::predicate_fragment`] is pinned on hold
    /// here and are pinned by sibling unit tests, because a guarantee that only
    /// half the fragments carry is not a guarantee:
    ///
    /// * **inline**, no `epigraph_*()` call;
    /// * **`visibility = 'public'` leads**, so it stays a syntactic match for
    ///   the leading disjunct of migration 077's `edges_tenancy` `USING`
    ///   clause (the clause is written out in migration 072's header, next to
    ///   the column, so PR-17 cannot re-derive a non-matching one);
    /// * **`Bypass` emits a single space**, not an empty string.
    ///
    /// `$V` appears TWICE and resolves to ONE bind index —
    /// [`Self::render_predicate`] replaces every occurrence — so a spliced
    /// statement still binds [`Self::group_bind`] exactly once.
    #[must_use]
    pub const fn edge_predicate_fragment(&self) -> &'static str {
        match self.shape {
            ViewerShape::Scoped { .. } => {
                " AND ({alias}.visibility = 'public' \
                   OR ({alias}.owner_group_id = ANY($V::uuid[]) \
                       AND ({alias}.co_owner_group_id IS NULL \
                            OR {alias}.co_owner_group_id = ANY($V::uuid[])))) "
            }
            ViewerShape::Bypass { .. } => " ",
        }
    }

    /// [`Self::predicate_fragment`] with its two placeholders filled in.
    ///
    /// `{alias}` becomes `alias`; `$V` becomes `$<bind_index>`. A `Bypass`
    /// viewer renders to `" "` — the same single space the fragment returns,
    /// preserved for the same reason (it is spliced between SQL tokens).
    ///
    /// `bind_index` is the positional parameter the caller will bind
    /// [`Self::group_bind`] to. It is the caller's job to pick a free one; there
    /// is no way for this function to know how many binds the surrounding
    /// statement already has.
    #[must_use]
    pub fn render_predicate(&self, alias: &str, bind_index: usize) -> String {
        self.render_fragment(self.predicate_fragment(), alias, bind_index)
    }

    /// [`Self::edge_predicate_fragment`] with its placeholders filled in.
    ///
    /// `{alias}` becomes `alias` at all four occurrences; **both** `$V`
    /// occurrences become the SAME `$<bind_index>`, so the statement still
    /// binds [`Self::group_bind`] once. A `Bypass` viewer renders to `" "`.
    #[must_use]
    pub fn render_edge_predicate(&self, alias: &str, bind_index: usize) -> String {
        self.render_fragment(self.edge_predicate_fragment(), alias, bind_index)
    }

    /// Shared substitution for both fragments.
    ///
    /// `Bypass` short-circuits to `" "` rather than running `replace` over the
    /// bypass fragment, so a `Bypass` render can never emit a `$` — the
    /// property `a_bypass_splice_leaves_no_bind_and_no_placeholder` asserts.
    fn render_fragment(&self, fragment: &'static str, alias: &str, bind_index: usize) -> String {
        match self.shape {
            ViewerShape::Bypass { .. } => " ".to_string(),
            ViewerShape::Scoped { .. } => fragment
                .replace("{alias}", alias)
                .replace("$V", &format!("${bind_index}")),
        }
    }

    /// Replace every `/* {VISIBILITY:<alias>} */` and
    /// `/* {EDGE_VISIBILITY:<alias>} */` marker in `sql` with
    /// [`Self::render_predicate`] / [`Self::render_edge_predicate`] for that
    /// alias, at `first_bind`.
    ///
    /// Every marker in one statement — of EITHER spelling — resolves to the
    /// SAME bind index. A statement with two CTEs over `claims` filters both
    /// and reads one `$V`; a statement joining `evidence e` to `edges ed`
    /// filters both with one `$V` too, one marker per spelling.
    ///
    /// # Panics
    ///
    /// Panics when `sql` contains no marker of either spelling. This is
    /// deliberate and it is the point of the function: a read that takes a
    /// `&Viewer` and does not use it is a fail-open that compiles, passes every
    /// "a stranger cannot read" test (because it returns *more*, not less), and
    /// is invisible in a diff. The input is a `&'static str` the developer wrote
    /// three lines above the call, so the panic is a compile-time-shaped error
    /// that happens to fire at first execution — the first test that touches the
    /// query, not a user-facing path.
    ///
    /// Also panics on a marker that is opened and never closed.
    #[must_use]
    pub fn splice(&self, sql: &str, first_bind: usize) -> String {
        assert!(
            sql.contains(VISIBILITY_MARKER_PREFIX) || sql.contains(EDGE_VISIBILITY_MARKER_PREFIX),
            "Viewer::splice called on SQL with no {VISIBILITY_MARKER_PREFIX}…{VISIBILITY_MARKER_SUFFIX} \
             or {EDGE_VISIBILITY_MARKER_PREFIX}…{VISIBILITY_MARKER_SUFFIX} \
             marker. A read that takes a Viewer and does not filter on it is a \
             fail-open. SQL was:\n{sql}"
        );

        // Two passes. The edge spelling goes FIRST only for readability: the two
        // prefixes are disjoint strings and neither rendered fragment contains
        // either prefix, so the passes are order-independent.
        let edges_done = self.substitute_markers(
            sql,
            EDGE_VISIBILITY_MARKER_PREFIX,
            |v, alias| v.render_edge_predicate(alias, first_bind),
            sql,
        );
        self.substitute_markers(
            &edges_done,
            VISIBILITY_MARKER_PREFIX,
            |v, alias| v.render_predicate(alias, first_bind),
            sql,
        )
    }

    /// One substitution pass for one marker spelling.
    ///
    /// `original` is the caller's SQL, carried through solely so a panic names
    /// the literal the developer wrote rather than a half-substituted string.
    fn substitute_markers(
        &self,
        sql: &str,
        prefix: &str,
        render: impl Fn(&Self, &str) -> String,
        original: &str,
    ) -> String {
        let mut out = String::with_capacity(sql.len() + 96);
        let mut rest = sql;
        while let Some(open) = rest.find(prefix) {
            out.push_str(&rest[..open]);
            let after_prefix = &rest[open + prefix.len()..];
            let close = after_prefix
                .find(VISIBILITY_MARKER_SUFFIX)
                .unwrap_or_else(|| {
                    panic!(
                        "unterminated visibility marker: expected \
                     {VISIBILITY_MARKER_SUFFIX} after {prefix} in:\n{original}"
                    )
                });
            let alias = after_prefix[..close].trim();
            assert!(
                !alias.is_empty(),
                "empty alias in visibility marker in:\n{original}"
            );
            out.push_str(&render(self, alias));
            rest = &after_prefix[close + VISIBILITY_MARKER_SUFFIX.len()..];
        }
        out.push_str(rest);
        out
    }

    /// The `$N::bool` bypass flag for the four `sqlx::query!` macro read sites,
    /// which cannot take a spliced literal.
    ///
    /// `true` disables the predicate the same way an emitted-nothing fragment
    /// does; `false` leaves `visibility = 'public' OR owner_group_id = ANY(...)`
    /// deciding. Pair it with [`Self::group_bind`]`.unwrap_or(&[])` — a `Bypass`
    /// viewer has no group bind, and the empty array is inert behind a `true`
    /// short-circuit.
    #[must_use]
    pub const fn bypass_bind(&self) -> bool {
        self.is_bypass()
    }

    /// `true` when this viewer emits no visibility predicate at all.
    #[must_use]
    pub const fn is_bypass(&self) -> bool {
        matches!(self.shape, ViewerShape::Bypass { .. })
    }

    /// The reason a bypass viewer exists, for logs and metrics.
    #[must_use]
    pub const fn bypass_reason(&self) -> Option<SystemReason> {
        match self.shape {
            ViewerShape::Bypass { reason } => Some(reason),
            ViewerShape::Scoped { .. } => None,
        }
    }

    /// Test-only scoped constructor.
    ///
    /// `#[cfg(test)]` is on the DEFINITION rather than behind a cargo feature
    /// on purpose: a feature can be switched on from a dependent crate's build
    /// graph, and then this constructor is reachable in production.
    ///
    /// The writable set is taken to equal the group set, which is the
    /// permissive choice — a test that wants to prove a *reader* cannot write
    /// must build its fixture through `resolve`.
    #[cfg(test)]
    #[must_use]
    pub fn test_scoped(principal: Uuid, group_ids: Vec<Uuid>) -> Self {
        let mut group_ids = group_ids;
        group_ids.sort_unstable();
        group_ids.dedup();
        let writable = group_ids.clone();
        Viewer {
            shape: ViewerShape::Scoped {
                principal,
                group_ids,
                writable,
            },
        }
    }

    /// Test-only `Bypass` viewer.
    ///
    /// Maintenance enumerators (`find_claims_needing_embeddings`,
    /// `MassFunctionRepository::list_claim_ids`, …) `debug_assert!(viewer.is_bypass())`
    /// precisely because a `Scoped` viewer there would silently skip every other
    /// tenant's rows — leaving them unembedded, or their beliefs stale, forever.
    /// Their tests therefore need a real `Bypass`, not a permissive `Scoped`.
    ///
    /// Production builds one only via `ScopedPool::unscoped_for_maintenance`,
    /// which hands back a [`MaintenanceLease`] proving the connection is a
    /// maintenance connection. That is deliberately heavy for an in-crate unit
    /// test, so this mirrors [`Self::test_scoped`] — including `#[cfg(test)]` on
    /// the DEFINITION, so no dependent crate's feature graph can make it
    /// reachable in production.
    #[cfg(test)]
    #[must_use]
    pub fn test_bypass(reason: SystemReason) -> Self {
        Viewer {
            shape: ViewerShape::Bypass { reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lists_every_variant_exactly_once() {
        // The exhaustive `match` that pairs with this lives in
        // tests/no_anonymous_viewer.rs, where it is compiled against the public
        // enum. Here we only check ALL has no duplicates.
        //
        // The COUNT deliberately is not asserted here. It is a
        // monotone-decreasing ratchet in tests/viewer_ratchet.rs, and PR-04
        // removed the `assert_eq!(…, 10)` from this file and from
        // no_anonymous_viewer.rs so the number lives in exactly one place. Three
        // equality assertions on one count is three files to edit the first time
        // a bypass is legitimately removed — which is how a ratchet quietly
        // stops ratcheting.
        let mut seen = std::collections::HashSet::new();
        for r in SystemReason::ALL {
            assert!(seen.insert(*r), "duplicate in SystemReason::ALL: {r:?}");
        }
        assert!(!SystemReason::ALL.is_empty());
    }

    #[test]
    fn reason_labels_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for r in SystemReason::ALL {
            assert!(seen.insert(r.as_str()), "duplicate label for {r:?}");
        }
    }

    #[test]
    fn scoped_viewer_exposes_principal_and_groups() {
        let principal = Uuid::new_v4();
        let g1 = Uuid::new_v4();
        let g2 = Uuid::new_v4();
        let v = Viewer::test_scoped(principal, vec![g2, g1, g1]);

        assert_eq!(v.principal(), Some(principal));
        assert!(!v.is_bypass());
        assert_eq!(v.bypass_reason(), None);

        let bind = v.group_bind().expect("scoped viewer binds its groups");
        assert_eq!(bind.len(), 2, "duplicates are collapsed");
        assert!(bind.windows(2).all(|w| w[0] < w[1]), "bind is sorted");
        assert_eq!(v.writable_groups().len(), 2);
    }

    #[test]
    fn bypass_viewer_has_no_principal_and_no_bind() {
        let lease = MaintenanceLease::new();
        let v = Viewer::system(&lease, SystemReason::EmbeddingBackfill);

        assert_eq!(v.principal(), None);
        assert_eq!(v.group_bind(), None);
        assert_eq!(v.writable_bind(), None);
        assert!(v.writable_groups().is_empty());
        assert!(v.is_bypass());
        assert_eq!(v.bypass_reason(), Some(SystemReason::EmbeddingBackfill));
    }

    /// Every shape, and every bypass reason, must map onto EXACTLY TWO distinct
    /// fragments. A third string would mean the predicate had grown a case, and
    /// a case is where a leak lives: the qual would no longer be a syntactic
    /// match for migration 077's `USING` clause on every path.
    #[test]
    fn predicate_fragment_has_exactly_two_distinct_values() {
        let lease = MaintenanceLease::new();

        let mut seen = std::collections::HashSet::new();
        seen.insert(Viewer::test_scoped(Uuid::new_v4(), vec![]).predicate_fragment());
        seen.insert(
            Viewer::test_scoped(Uuid::new_v4(), vec![Uuid::new_v4(), Uuid::new_v4()])
                .predicate_fragment(),
        );
        for reason in SystemReason::ALL {
            seen.insert(Viewer::system(&lease, *reason).predicate_fragment());
        }

        assert_eq!(
            seen.len(),
            2,
            "predicate_fragment must return exactly two distinct strings \
             (one per shape); got {seen:?}"
        );
    }

    #[test]
    fn bypass_fragment_is_a_separator_not_an_empty_string() {
        let lease = MaintenanceLease::new();
        let frag = Viewer::system(&lease, SystemReason::DedupSweep).predicate_fragment();
        assert_eq!(frag, " ");
        assert!(
            !frag.is_empty(),
            "an empty fragment would concatenate the tokens it is spliced between"
        );
    }

    /// The shape of the `Scoped` fragment, asserted rather than described.
    #[test]
    fn scoped_fragment_is_inline_ordered_and_single_bind() {
        let frag = Viewer::test_scoped(Uuid::new_v4(), vec![Uuid::new_v4()]).predicate_fragment();

        // No helper-function call: an `epigraph_visible(...)` here would rest on
        // an inlining assumption and add a surface to REVOKE.
        assert!(
            !frag.contains("epigraph_"),
            "the Scoped fragment must be written inline, not as a function call: {frag}"
        );

        // `{alias}` is substituted by the caller, once per disjunct.
        assert_eq!(
            frag.matches("{alias}").count(),
            2,
            "both disjuncts must be alias-qualified: {frag}"
        );

        // One bind, not two: `$V` is the single optional parameter.
        assert_eq!(
            frag.matches("$V").count(),
            1,
            "the Scoped fragment takes exactly one bind: {frag}"
        );

        // ORDERING. `visibility = 'public'` must lead — cheap-first for the
        // executor, and it is the leading disjunct of migration 077's USING.
        let public_at = frag
            .find("visibility = 'public'")
            .expect("the public disjunct must be present verbatim");
        let group_at = frag
            .find("owner_group_id")
            .expect("the group disjunct must be present");
        assert!(
            public_at < group_at,
            "`visibility = 'public'` must come first: {frag}"
        );

        // It is spliceable: leading ` AND `, and it does not close a paren it
        // did not open.
        assert!(frag.starts_with(" AND ("), "fragment shape changed: {frag}");
        assert_eq!(
            frag.matches('(').count(),
            frag.matches(')').count(),
            "unbalanced parentheses: {frag}"
        );
    }

    /// The sibling of `predicate_fragment_has_exactly_two_distinct_values`, for
    /// the same reason and with the same teeth.
    ///
    /// PR-13 added a second fragment. Without this test the two-value guarantee
    /// would silently cover only half the fragments in the module — and it would
    /// stay GREEN while doing so, which is the failure mode a ratchet exists to
    /// prevent.
    #[test]
    fn edge_predicate_fragment_has_exactly_two_distinct_values() {
        let lease = MaintenanceLease::new();

        let mut seen = std::collections::HashSet::new();
        seen.insert(Viewer::test_scoped(Uuid::new_v4(), vec![]).edge_predicate_fragment());
        seen.insert(
            Viewer::test_scoped(Uuid::new_v4(), vec![Uuid::new_v4(), Uuid::new_v4()])
                .edge_predicate_fragment(),
        );
        for reason in SystemReason::ALL {
            seen.insert(Viewer::system(&lease, *reason).edge_predicate_fragment());
        }

        assert_eq!(
            seen.len(),
            2,
            "edge_predicate_fragment must return exactly two distinct strings \
             (one per shape); got {seen:?}"
        );
    }

    /// The sibling of `scoped_fragment_is_inline_ordered_and_single_bind`.
    ///
    /// Same three properties, plus the one that is specific to this fragment:
    /// the group clause is an INTERSECTION (`AND`), not a union. A union would
    /// make the co-ownership column decorative — membership in G alone would
    /// show an edge naming H's private claim.
    #[test]
    fn scoped_edge_fragment_is_inline_ordered_and_an_intersection() {
        let frag =
            Viewer::test_scoped(Uuid::new_v4(), vec![Uuid::new_v4()]).edge_predicate_fragment();

        assert!(
            !frag.contains("epigraph_"),
            "the Scoped edge fragment must be written inline: {frag}"
        );

        // Four alias-qualified column references: visibility, owner_group_id,
        // and co_owner_group_id twice.
        assert_eq!(
            frag.matches("{alias}").count(),
            4,
            "every column reference must be alias-qualified: {frag}"
        );

        // ONE bind index, TWO occurrences. `render_predicate`'s `replace`
        // rewrites every `$V`, so a spliced statement still binds the group
        // array once — asserted end-to-end in
        // `an_edge_marker_binds_one_index_at_both_co_owner_occurrences`.
        assert_eq!(
            frag.matches("$V").count(),
            2,
            "the edge fragment reads the viewer's groups twice, at one bind: {frag}"
        );

        // ORDERING, as in the plain fragment: `visibility = 'public'` leads.
        let public_at = frag
            .find("visibility = 'public'")
            .expect("the public disjunct must be present verbatim");
        let owner_at = frag
            .find("owner_group_id")
            .expect("the group disjunct must be present");
        assert!(
            public_at < owner_at,
            "`visibility = 'public'` must come first: {frag}"
        );

        // THE INTERSECTION. `owner_group_id = ANY(...)` must be joined to the
        // co-owner clause by AND, not OR. Written as a positional assertion
        // rather than a substring match on a hand-copied clause, so a
        // reformatting of the fragment does not make it vacuous.
        let co_at = frag
            .find("co_owner_group_id")
            .expect("the co-owner clause must be present");
        let between = &frag[owner_at..co_at];
        assert!(
            between.contains(" AND "),
            "the co-owner clause must INTERSECT the owner clause, not union \
             with it — a union makes co-ownership decorative: {frag}"
        );
        assert!(
            !between.contains(" OR "),
            "the co-owner clause must not be a disjunct of the owner clause: {frag}"
        );

        // NULL is the single-owner case and must short-circuit the whole
        // co-owner test.
        assert!(
            frag.contains("co_owner_group_id IS NULL"),
            "a single-owner edge (co_owner IS NULL) must remain visible to the \
             owning group: {frag}"
        );

        assert!(frag.starts_with(" AND ("), "fragment shape changed: {frag}");
        assert_eq!(
            frag.matches('(').count(),
            frag.matches(')').count(),
            "unbalanced parentheses: {frag}"
        );
    }

    /// The two fragments are not the same string, and neither is a `Bypass`
    /// fragment. Cheap, and it catches a copy-paste that would silently drop
    /// the co-ownership conjunct from every edge read.
    #[test]
    fn the_edge_fragment_is_not_the_plain_fragment() {
        let v = Viewer::test_scoped(Uuid::new_v4(), vec![Uuid::new_v4()]);
        assert_ne!(v.predicate_fragment(), v.edge_predicate_fragment());
        assert!(!v.predicate_fragment().contains("co_owner_group_id"));

        // The two shapes still agree on Bypass: one space, both fragments.
        let lease = MaintenanceLease::new();
        let b = Viewer::system(&lease, SystemReason::DedupSweep);
        assert_eq!(b.predicate_fragment(), " ");
        assert_eq!(b.edge_predicate_fragment(), " ");
    }

    #[test]
    fn an_edge_marker_binds_one_index_at_both_co_owner_occurrences() {
        let v = Viewer::test_scoped(Uuid::new_v4(), vec![Uuid::new_v4()]);
        let sql = "SELECT 1 FROM edges e WHERE e.valid_to IS NULL \
                   /* {EDGE_VISIBILITY:e} */";
        let out = v.splice(sql, 3);

        assert_eq!(
            out.matches("$3").count(),
            2,
            "both group reads resolve to the caller's single bind: {out}"
        );
        assert_eq!(out.matches("e.co_owner_group_id").count(), 2);
        assert!(
            !out.contains(EDGE_VISIBILITY_MARKER_PREFIX),
            "marker survived"
        );
        assert!(!out.contains("{alias}"), "alias left unsubstituted: {out}");
    }

    /// `repos/evidence.rs::provided_for_claim_as_of`'s shape: `e` is `evidence`
    /// and `ed` is `edges`, in ONE statement. This is the collision that makes a
    /// second marker spelling necessary rather than merely tidy — an
    /// alias-keyed dispatch would have to give both aliases the same fragment.
    #[test]
    fn both_marker_spellings_coexist_in_one_statement_at_one_bind() {
        let v = Viewer::test_scoped(Uuid::new_v4(), vec![Uuid::new_v4()]);
        let sql = "SELECT 1 FROM evidence e JOIN edges ed ON ed.target_id = e.id \
                   WHERE true /* {VISIBILITY:e} */ /* {EDGE_VISIBILITY:ed} */";
        let out = v.splice(sql, 5);

        // evidence took the plain fragment; edges took the co-ownership one.
        assert!(
            !out.contains("e.co_owner_group_id"),
            "the plain fragment must not name a column `evidence` does not have: {out}"
        );
        assert_eq!(out.matches("ed.co_owner_group_id").count(), 2);
        // One bind index across both spellings: 1 (evidence) + 2 (edges).
        assert_eq!(out.matches("$5").count(), 3, "{out}");
        assert!(!out.contains(VISIBILITY_MARKER_PREFIX), "{out}");
        assert!(!out.contains(EDGE_VISIBILITY_MARKER_PREFIX), "{out}");
    }

    /// The missing-marker panic must still fire for a statement carrying
    /// neither spelling — widening the assertion to accept the edge marker must
    /// not have widened it to accept nothing.
    #[test]
    #[should_panic(expected = "no")]
    fn splicing_a_literal_with_neither_spelling_still_panics() {
        let v = Viewer::test_scoped(Uuid::new_v4(), vec![]);
        let _ = v.splice("SELECT * FROM edges WHERE valid_to IS NULL", 1);
    }

    #[test]
    fn a_bypass_edge_splice_leaves_no_bind_and_no_placeholder() {
        let lease = MaintenanceLease::new();
        let v = Viewer::system(&lease, SystemReason::SchemaContractTest);
        let sql = "SELECT 1 FROM edges e WHERE true /* {EDGE_VISIBILITY:e} */ AND true";
        let out = v.splice(sql, 4);

        assert!(!out.contains('$'), "a bypass splice binds nothing: {out}");
        assert!(!out.contains("co_owner_group_id"), "{out}");
        assert!(!out.contains(EDGE_VISIBILITY_MARKER_PREFIX), "{out}");
    }

    #[test]
    fn render_substitutes_both_placeholders() {
        let v = Viewer::test_scoped(Uuid::new_v4(), vec![Uuid::new_v4()]);
        let rendered = v.render_predicate("c", 7);

        assert!(!rendered.contains("{alias}"), "alias left unsubstituted");
        assert!(!rendered.contains("$V"), "bind left unsubstituted");
        assert_eq!(rendered.matches("c.").count(), 2);
        assert_eq!(rendered.matches("$7").count(), 1);
    }

    /// The `search_hybrid_scoped_since` shape: two CTEs over `claims`, one bind.
    #[test]
    fn splicing_two_markers_yields_one_bind_index_twice() {
        let v = Viewer::test_scoped(Uuid::new_v4(), vec![Uuid::new_v4()]);
        let sql = "WITH dense AS (SELECT 1 FROM claims c WHERE c.is_current /* {VISIBILITY:c} */ LIMIT $3), \
                   lex AS (SELECT 1 FROM claims c WHERE c.is_current /* {VISIBILITY:c} */ LIMIT $3) \
                   SELECT * FROM dense";
        let out = v.splice(sql, 9);

        assert_eq!(out.matches("$9").count(), 2, "both CTEs read the same bind");
        assert_eq!(
            out.matches("visibility = 'public'").count(),
            2,
            "both CTEs are filtered: {out}"
        );
        assert!(!out.contains(VISIBILITY_MARKER_PREFIX), "marker survived");
    }

    #[test]
    fn splicing_distinct_aliases_qualifies_each_independently() {
        let v = Viewer::test_scoped(Uuid::new_v4(), vec![Uuid::new_v4()]);
        let sql = "SELECT 1 FROM challenges ch JOIN claims c ON c.id = ch.claim_id \
                   WHERE true /* {VISIBILITY:ch} */ /* {VISIBILITY:c} */";
        let out = v.splice(sql, 2);

        assert_eq!(out.matches("ch.visibility").count(), 1);
        assert_eq!(out.matches("c.visibility").count(), 1);
        assert_eq!(out.matches("$2").count(), 2);
    }

    #[test]
    fn a_bypass_splice_leaves_no_bind_and_no_placeholder() {
        let lease = MaintenanceLease::new();
        let v = Viewer::system(&lease, SystemReason::SchemaContractTest);
        let sql = "SELECT 1 FROM claims c WHERE c.is_current /* {VISIBILITY:c} */ AND true";
        let out = v.splice(sql, 4);

        assert!(!out.contains('$'), "a bypass splice binds nothing: {out}");
        assert!(!out.contains("{alias}"), "{out}");
        assert!(!out.contains(VISIBILITY_MARKER_PREFIX), "{out}");
        assert!(
            out.contains("c.is_current   AND true") || out.contains("c.is_current  AND true"),
            "the bypass fragment separates the tokens it sat between: {out}"
        );
    }

    #[test]
    #[should_panic(expected = "no")]
    fn splicing_a_marker_free_literal_panics() {
        let v = Viewer::test_scoped(Uuid::new_v4(), vec![]);
        let _ = v.splice("SELECT * FROM claims WHERE is_current = true", 1);
    }

    #[test]
    fn bypass_bind_tracks_the_shape() {
        let lease = MaintenanceLease::new();
        assert!(Viewer::system(&lease, SystemReason::DedupSweep).bypass_bind());
        assert!(!Viewer::test_scoped(Uuid::new_v4(), vec![]).bypass_bind());
    }

    #[test]
    fn writable_bind_mirrors_group_bind_for_a_scoped_viewer() {
        let principal = Uuid::new_v4();
        let g = Uuid::new_v4();
        let v = Viewer::test_scoped(principal, vec![g]);

        assert_eq!(v.group_bind(), Some(&[g][..]));
        assert_eq!(v.writable_bind(), Some(&[g][..]));
    }
}
