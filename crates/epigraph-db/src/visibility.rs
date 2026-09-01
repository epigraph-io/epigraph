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
//! * [`VISIBILITY_MARKER_PREFIX`] is the single spelling of the marker, shared
//!   with `crates/epigraph-db/tests/visibility_lint.rs`, so the lint and the
//!   repo layer cannot drift apart.
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
//! `edge_predicate_fragment` — the `edges` variant that carries the co-ownership
//! INTERSECTION — is still deferred, now to **PR-13**. Plan §4.3 defines it in
//! terms of `edges.co_owner_group_id`, a column PR-13's migration creates. A
//! fragment naming a column that does not exist is compile-time-clean and
//! runtime-fatal, which is exactly the shape this note exists to prevent, so
//! `edges` reads use [`Viewer::predicate_fragment`] until PR-13 widens them.

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

/// The closing half of the marker, split out so the two halves are never
/// written as separate literals at a call site.
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
    /// The `edges` variant carrying the co-ownership INTERSECTION
    /// (`edges.co_owner_group_id`) is deferred to PR-13, which creates that
    /// column. See the module docs.
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
        match self.shape {
            ViewerShape::Bypass { .. } => " ".to_string(),
            ViewerShape::Scoped { .. } => self
                .predicate_fragment()
                .replace("{alias}", alias)
                .replace("$V", &format!("${bind_index}")),
        }
    }

    /// Replace every `/* {VISIBILITY:<alias>} */` marker in `sql` with
    /// [`Self::render_predicate`] for that alias, at `first_bind`.
    ///
    /// Every marker in one statement resolves to the SAME bind index — a
    /// statement with two CTEs over `claims` filters both and reads one `$V`.
    ///
    /// # Panics
    ///
    /// Panics when `sql` contains no marker at all. This is deliberate and it is
    /// the point of the function: a read that takes a `&Viewer` and does not use
    /// it is a fail-open that compiles, passes every "a stranger cannot read"
    /// test (because it returns *more*, not less), and is invisible in a diff.
    /// The input is a `&'static str` the developer wrote three lines above the
    /// call, so the panic is a compile-time-shaped error that happens to fire at
    /// first execution — the first test that touches the query, not a
    /// user-facing path.
    ///
    /// Also panics on a marker that is opened and never closed.
    #[must_use]
    pub fn splice(&self, sql: &str, first_bind: usize) -> String {
        assert!(
            sql.contains(VISIBILITY_MARKER_PREFIX),
            "Viewer::splice called on SQL with no {VISIBILITY_MARKER_PREFIX}…{VISIBILITY_MARKER_SUFFIX} \
             marker. A read that takes a Viewer and does not filter on it is a \
             fail-open. SQL was:\n{sql}"
        );

        let mut out = String::with_capacity(sql.len() + 96);
        let mut rest = sql;
        while let Some(open) = rest.find(VISIBILITY_MARKER_PREFIX) {
            out.push_str(&rest[..open]);
            let after_prefix = &rest[open + VISIBILITY_MARKER_PREFIX.len()..];
            let close = after_prefix
                .find(VISIBILITY_MARKER_SUFFIX)
                .unwrap_or_else(|| {
                    panic!(
                        "unterminated visibility marker: expected \
                     {VISIBILITY_MARKER_SUFFIX} after {VISIBILITY_MARKER_PREFIX} in:\n{sql}"
                    )
                });
            let alias = after_prefix[..close].trim();
            assert!(
                !alias.is_empty(),
                "empty alias in visibility marker in:\n{sql}"
            );
            out.push_str(&self.render_predicate(alias, first_bind));
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
