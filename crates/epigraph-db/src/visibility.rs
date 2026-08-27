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
//! # What is deliberately NOT here yet
//!
//! `predicate_fragment` / `edge_predicate_fragment` — the SQL a `Viewer` emits —
//! land in PR-04 alongside the tenancy columns they reference
//! (`claims.visibility`, `claims.owner_group_id`). Emitting a predicate against
//! columns that do not exist yet would be a compile-time-clean, runtime-fatal
//! change.

use crate::errors::DbError;
use crate::repos::GroupMembershipRepository;
use sqlx::PgPool;
use uuid::Uuid;

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
    /// group. It does not yet, because personal groups do not exist until
    /// PR-04 adds `ensure_personal_group`. That obligation is parked as a
    /// failing `#[ignore]`d test —
    /// `no_anonymous_viewer.rs::resolve_unions_in_the_principals_personal_group`
    /// — rather than as prose here, because the failure mode is silent: a PR-04
    /// that lands the groups without the union produces `Scoped` viewers that
    /// read only `visibility = 'public'` forever, and the symptom looks like
    /// "the corpus is empty for new users", not like a bug in `resolve`.
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
    /// Mint a lease. Crate-private: PR-04's `ScopedPool` is the only intended
    /// caller, and it mints one only after handing out a connection on the
    /// maintenance role.
    #[allow(dead_code)] // the ScopedPool that calls this lands in PR-04
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lists_every_variant_exactly_once() {
        // The exhaustive `match` that pairs with this lives in
        // tests/no_anonymous_viewer.rs, where it is compiled against the public
        // enum. Here we only check ALL has no duplicates and no gaps in count.
        let mut seen = std::collections::HashSet::new();
        for r in SystemReason::ALL {
            assert!(seen.insert(*r), "duplicate in SystemReason::ALL: {r:?}");
        }
        assert_eq!(SystemReason::ALL.len(), 10);
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
        assert!(v.writable_groups().is_empty());
        assert!(v.is_bypass());
        assert_eq!(v.bypass_reason(), Some(SystemReason::EmbeddingBackfill));
    }
}
